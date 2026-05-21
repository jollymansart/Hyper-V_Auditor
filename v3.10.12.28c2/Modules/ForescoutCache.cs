using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Threading;
using System.Diagnostics;
using OfficeOpenXml;



// ============================================================================
// ASSEMBLY VERSION ATTRIBUTES
// ============================================================================
// 
// IMPORTANT: Update these three version numbers when releasing new versions!
// Keep them synchronized with:
//   - ForescoutCache.csproj <Version>
//   - ForescoutCache.psd1 ModuleVersion
//
// Version Format: Major.Minor.Build.Revision
//   Example: 1.0.1.0 = Version 1.0.1, Build 0
//
// ============================================================================

[assembly: System.Reflection.AssemblyVersion("1.0.1.0")]
    // Binary version - affects assembly loading
    // Format: Major.Minor.Build.Revision
    // Change this when making breaking changes

[assembly: System.Reflection.AssemblyFileVersion("1.0.1.0")]
    // File version - shown in Windows file properties
    // Format: Major.Minor.Build.Revision
    // Increment for each build

[assembly: System.Reflection.AssemblyInformationalVersion("1.0.1")]
    // Product/display version - user-friendly version string
    // Format: Major.Minor.Build (can include labels like "1.0.1-beta")
    // This is what users see

// ============================================================================
// ASSEMBLY METADATA ATTRIBUTES
// ============================================================================

[assembly: System.Reflection.AssemblyTitle("ForescoutCache")]
[assembly: System.Reflection.AssemblyDescription("High-performance Forescout data cache with intelligent incremental loading. Provides 5-9x faster performance than PowerShell-only solutions with 90% less memory usage.")]
[assembly: System.Reflection.AssemblyCompany("Overhead Door Corporation")]
[assembly: System.Reflection.AssemblyProduct("ForescoutCache - High-Performance Forescout Data Cache")]
[assembly: System.Reflection.AssemblyCopyright("Copyright © 2025 Michael David George michael.d.george@outlook.com mdg.mike.george@gmail.com, Overhead Door Corporation")]
[assembly: System.Reflection.AssemblyTrademark("")]
[assembly: System.Reflection.AssemblyCulture("")]
[assembly: System.Reflection.AssemblyConfiguration("Release")]

// ============================================================================
// COM VISIBILITY (Optional - not needed for this project)
// ============================================================================
// [assembly: System.Runtime.InteropServices.ComVisible(false)]



namespace ForescoutCache
{
    /// <summary>
    /// High-performance in-memory cache for Forescout dump files
    /// Features: Incremental loading, memory management, thread-safe operations
    /// </summary>
    public class ForescoutCacheManager : IDisposable
    {
        #region Private Fields
        
        private readonly ConcurrentDictionary<string, ForescoutRecord> _macIndex;
        private readonly ConcurrentDictionary<string, FileMetadata> _loadedFiles;
        private readonly string _searchPath;
        private readonly List<FileInfo> _fileList;
        private readonly object _loadLock = new object();
        private readonly PerformanceCounter? _memoryCounter;
        private int _currentFileIndex = 0;
        private long _totalRecordsLoaded = 0;
        private long _totalMemoryBytes = 0;
        private bool _disposed = false;
        
        // Required columns from Forescout dumps
        private static readonly string[] RequiredColumns = new[]
        {
            "Host", "IPv4 Address", "Segment", "Access IP", "MAC Address",
            "Switch Hostname", "Switch IP/FQDN and Port Name", "Switch IP/FQDN",
            "Switch Port Name", "Switch Port Alias", "Switch Port VLAN", "Switch Port VLAN Name"
        };
        
        #endregion
        
        #region Public Properties
        
        /// <summary>
        /// Total number of unique MAC addresses loaded in cache
        /// </summary>
        public int TotalMacAddresses => _macIndex.Count;
        
        /// <summary>
        /// Number of files currently loaded in memory
        /// </summary>
        public int FilesLoaded => _loadedFiles.Count;
        
        /// <summary>
        /// Total number of records loaded across all files
        /// </summary>
        public long TotalRecordsLoaded => _totalRecordsLoaded;
        
        /// <summary>
        /// Estimated memory usage in MB
        /// </summary>
        public double EstimatedMemoryMB => _totalMemoryBytes / (1024.0 * 1024.0);
        
        /// <summary>
        /// Current system memory pressure (0-100%)
        /// </summary>
        /// <summary>
        /// Current system memory pressure (0-100%)
        /// </summary>
        public double MemoryPressurePercent
        {
            get
            {
                try
                {
#if NET8_0_OR_GREATER
                    // Modern .NET: use GC.GetGCMemoryInfo (not available on .NET Framework)
                    var gcMemInfo = GC.GetGCMemoryInfo();
                    var heapSizeBytes = gcMemInfo.HeapSizeBytes;
                    var memoryLoadBytes = gcMemInfo.MemoryLoadBytes;
                    if (memoryLoadBytes > 0)
                    {
                        return (heapSizeBytes / (double)memoryLoadBytes) * 100;
                    }
                    // Fallback to process memory if the runtime reports 0
                    using (var process = Process.GetCurrentProcess())
                    {
                        var totalMemory = GC.GetTotalMemory(false);
                        var workingSet = process.WorkingSet64;
                        return workingSet > 0 ? (totalMemory / (double)workingSet) * 100 : 0;
                    }
#else
                    // .NET Framework: no GetGCMemoryInfo; use process working set as a rough proxy
                    using (var process = Process.GetCurrentProcess())
                    {
                        var totalMemory = GC.GetTotalMemory(false);   // managed heap
                        var workingSet = process.WorkingSet64;        // physical memory in use by this process
                        return workingSet > 0 ? (totalMemory / (double)workingSet) * 100 : 0;
                    }
#endif
                }
                catch
                {
                    return 0;
                }
            }
        }
        
        /// <summary>
        /// Status information for monitoring
        /// </summary>
        public CacheStatus GetStatus()
        {
            return new CacheStatus
            {
                TotalMacAddresses = TotalMacAddresses,
                FilesLoaded = FilesLoaded,
                TotalRecordsLoaded = TotalRecordsLoaded,
                EstimatedMemoryMB = EstimatedMemoryMB,
                MemoryPressurePercent = MemoryPressurePercent,
                CurrentFileIndex = _currentFileIndex,
                TotalFilesAvailable = _fileList.Count,
                IsMemoryPressureHigh = MemoryPressurePercent > 75,
                LoadedFileNames = _loadedFiles.Values.Select(f => f.FileName).ToList()
            };
        }
        
        #endregion
        
        #region Constructor
        
        /// <summary>
        /// Initialize the Forescout cache manager
        /// </summary>
        /// <param name="searchPath">Path containing Forescout dump files (CSV/XLSX)</param>
        public ForescoutCacheManager(string searchPath)
        {
            if (string.IsNullOrWhiteSpace(searchPath))
                throw new ArgumentException("Search path cannot be null or empty", nameof(searchPath));
            
            if (!Directory.Exists(searchPath))
                throw new DirectoryNotFoundException($"Search path not found: {searchPath}");
            
            _searchPath = searchPath;
            _macIndex = new ConcurrentDictionary<string, ForescoutRecord>(StringComparer.OrdinalIgnoreCase);
            _loadedFiles = new ConcurrentDictionary<string, FileMetadata>(StringComparer.OrdinalIgnoreCase);
            
            // Get file list ordered by newest first (CSV before XLSX for performance)
            var csvFiles = Directory.GetFiles(searchPath, "*.csv", SearchOption.TopDirectoryOnly)
                .Select(f => new FileInfo(f))
                .OrderByDescending(f => f.LastWriteTime);
            
            var xlsxFiles = Directory.GetFiles(searchPath, "*.xlsx", SearchOption.TopDirectoryOnly)
                .Select(f => new FileInfo(f))
                .OrderByDescending(f => f.LastWriteTime);
            
            _fileList = csvFiles.Concat(xlsxFiles).ToList();
            
            if (_fileList.Count == 0)
                throw new FileNotFoundException($"No CSV or XLSX files found in: {searchPath}");
            
            // EPPlus license - Fully qualify to avoid namespace ambiguity
            // ExcelPackage.LicenseContext = OfficeOpenXml.LicenseContext.NonCommercial;
        }
        
        #endregion
        
        #region Public Methods
        
        /// <summary>
        /// Search for a MAC address with incremental file loading
        /// Only loads files as needed until MAC is found
        /// </summary>
        /// <param name="macAddress">MAC address in any format</param>
        /// <returns>ForescoutRecord if found, null otherwise</returns>
        public SearchResult? SearchMac(string macAddress)
        {
            if (string.IsNullOrWhiteSpace(macAddress))
                throw new ArgumentException("MAC address cannot be null or empty", nameof(macAddress));
            
            var stopwatch = Stopwatch.StartNew();
            var normalizedMac = NormalizeMacAddress(macAddress);
            
            // Debug logging
            Console.WriteLine($"[DEBUG] SearchMac called");
            Console.WriteLine($"  Input: '{macAddress}' → Normalized: '{normalizedMac}'");
            Console.WriteLine($"  Dictionary size: {_macIndex.Count} entries");
            Console.WriteLine($"  Sample keys: {string.Join(", ", _macIndex.Keys.Take(5).Select(k => $"'{k}'"))}");
            Console.WriteLine($"  ContainsKey test: {_macIndex.ContainsKey(normalizedMac)}");
            
            // Check if already in cache
            if (_macIndex.TryGetValue(normalizedMac, out var cachedRecord))
            {
                stopwatch.Stop();
                return new SearchResult
                {
                    Record = cachedRecord,
                    Found = true,
                    SearchTimeMs = stopwatch.ElapsedMilliseconds,
                    FilesSearched = 0, // Found in cache
                    WasInCache = true,
                    Status = "Found in cache"
                };
            }
            
            // Not in cache - need to load more files incrementally
            int filesSearchedThisQuery = 0;
            
            while (_currentFileIndex < _fileList.Count)
            {
                lock (_loadLock)
                {
                    // Double-check after acquiring lock
                    if (_currentFileIndex >= _fileList.Count)
                        break;
                    
                    var file = _fileList[_currentFileIndex];
                    filesSearchedThisQuery++;
                    
                    // Load this file into cache
                    var loadResult = LoadFileIntoCache(file);
                    
                    if (!loadResult.Success)
                    {
                        _currentFileIndex++;
                        continue;
                    }
                    
                    _currentFileIndex++;
                    
                    // Check if our MAC is now in cache
                    if (_macIndex.TryGetValue(normalizedMac, out var foundRecord))
                    {
                        stopwatch.Stop();
                        return new SearchResult
                        {
                            Record = foundRecord,
                            Found = true,
                            SearchTimeMs = stopwatch.ElapsedMilliseconds,
                            FilesSearched = filesSearchedThisQuery,
                            WasInCache = false,
                            Status = $"Found in file: {file.Name}"
                        };
                    }
                }
            }
            
            // Not found in any file
            stopwatch.Stop();
            return new SearchResult
            {
                Record = null,
                Found = false,
                SearchTimeMs = stopwatch.ElapsedMilliseconds,
                FilesSearched = filesSearchedThisQuery,
                WasInCache = false,
                Status = $"Not found after searching {_currentFileIndex} of {_fileList.Count} files"
            };
        }
        
        /// <summary>
        /// Preload a specific number of files into cache
        /// </summary>
        /// <param name="fileCount">Number of files to preload (0 = all files)</param>
        public PreloadResult PreloadFiles(int fileCount = 0)
        {
            var stopwatch = Stopwatch.StartNew();
            var result = new PreloadResult();
            
            int targetFiles = fileCount <= 0 ? _fileList.Count : Math.Min(fileCount, _fileList.Count);
            
            while (_currentFileIndex < targetFiles)
            {
                lock (_loadLock)
                {
                    if (_currentFileIndex >= targetFiles)
                        break;
                    
                    var file = _fileList[_currentFileIndex];
                    var loadResult = LoadFileIntoCache(file);
                    
                    if (loadResult.Success)
                    {
                        result.FilesLoaded++;
                        result.RecordsLoaded += loadResult.RecordsLoaded;
                    }
                    else
                    {
                        result.FilesFailed++;
                        result.Errors.Add($"{file.Name}: {loadResult.ErrorMessage}");
                    }
                    
                    _currentFileIndex++;
                }
            }
            
            stopwatch.Stop();
            result.LoadTimeMs = stopwatch.ElapsedMilliseconds;
            result.Status = GetStatus();
            
            return result;
        }
        
        /// <summary>
        /// Clear all cached data and reset to initial state
        /// </summary>
        public void ClearCache()
        {
            lock (_loadLock)
            {
                _macIndex.Clear();
                _loadedFiles.Clear();
                _currentFileIndex = 0;
                _totalRecordsLoaded = 0;
                _totalMemoryBytes = 0;
                
                // Force garbage collection
                GC.Collect(2, GCCollectionMode.Forced, true, true);
                GC.WaitForPendingFinalizers();
                GC.Collect(2, GCCollectionMode.Forced, true, true);
            }
        }
        
        #endregion
        
        #region Private Methods
        
        /// <summary>
        /// Load a single file into the cache
        /// </summary>
        private FileLoadResult LoadFileIntoCache(FileInfo file)
        {
            var stopwatch = Stopwatch.StartNew();
            var result = new FileLoadResult { FileName = file.Name };
            
            try
            {
                // Skip if already loaded
                if (_loadedFiles.ContainsKey(file.FullName))
                {
                    result.Success = true;
                    result.ErrorMessage = "Already loaded";
                    return result;
                }
                
                List<Dictionary<string, string>> records;
                
                if (file.Extension.Equals(".csv", StringComparison.OrdinalIgnoreCase))
                {
                    records = LoadCsvFile(file.FullName);
                }
                else if (file.Extension.Equals(".xlsx", StringComparison.OrdinalIgnoreCase))
                {
                    records = LoadXlsxFile(file.FullName);
                }
                else
                {
                    result.ErrorMessage = $"Unsupported file type: {file.Extension}";
                    return result;
                }
                
                // Add records to MAC index
                int recordsAdded = 0;
                foreach (var record in records)
                {
                    if (record.TryGetValue("MAC Address", out var macAddress) && !string.IsNullOrWhiteSpace(macAddress))
                    {
                        var normalizedMac = NormalizeMacAddress(macAddress);
                        
                        // Only add if not already in index (first occurrence wins - newest file)
                        if (!_macIndex.ContainsKey(normalizedMac))
                        {
                            var forescoutRecord = new ForescoutRecord
                            {
                                Host = record.GetValueOrDefault("Host", ""),
                                IPv4Address = record.GetValueOrDefault("IPv4 Address", ""),
                                Segment = record.GetValueOrDefault("Segment", ""),
                                AccessIP = record.GetValueOrDefault("Access IP", ""),
                                MacAddress = macAddress,
                                SwitchHostname = record.GetValueOrDefault("Switch Hostname", ""),
                                SwitchIPFQDNAndPortName = record.GetValueOrDefault("Switch IP/FQDN and Port Name", ""),
                                SwitchIPFQDN = record.GetValueOrDefault("Switch IP/FQDN", ""),
                                SwitchPortName = record.GetValueOrDefault("Switch Port Name", ""),
                                SwitchPortAlias = record.GetValueOrDefault("Switch Port Alias", ""),
                                SwitchPortVLAN = record.GetValueOrDefault("Switch Port VLAN", ""),
                                SwitchPortVLANName = record.GetValueOrDefault("Switch Port VLAN Name", ""),
                                SourceFilePath = file.FullName,
                                SourceFileName = file.Name,
                                
                                // Additional printer/network identification columns
                                NICVendor = record.GetValueOrDefault("NIC Vendor", ""),
                                NICVendorValue = record.GetValueOrDefault("NIC Vendor Value", ""),
                                SensorSideIPv4 = record.GetValueOrDefault("Sensor-side IPv4", ""),
                                QfabricEndpointMac = record.GetValueOrDefault("Qfabric Endpoint Mac", ""),
                                QfabricEndpointMacTroubleshooting = record.GetValueOrDefault("Qfabric Endpoint Mac (Troubleshooting)", ""),
                                SwitchPortACL = record.GetValueOrDefault("Switch Port ACL", ""),
                                SwitchPortACLTroubleshooting = record.GetValueOrDefault("Switch Port ACL (Troubleshooting)", ""),
                                SwitchPortAliasTroubleshooting = record.GetValueOrDefault("Switch Port Alias (Troubleshooting)", "")
                            };
                            
                            _macIndex.TryAdd(normalizedMac, forescoutRecord);
                            recordsAdded++;
                        }
                    }
                }
                
                // Debug: Show sample of stored MAC addresses (first file only)
                if (recordsAdded > 0 && _macIndex.Count == recordsAdded)
                {
                    Console.WriteLine($"[DEBUG] Loaded {recordsAdded} MAC addresses from {file.Name}");
                    Console.WriteLine($"[DEBUG] Sample MACs stored (first 5):");
                    int count = 0;
                    foreach (var kvp in _macIndex)
                    {
                        Console.WriteLine($"  '{kvp.Key}' → Host: '{kvp.Value.Host}'");
                        if (++count >= 5) break;
                    }
                }
                
                // Track file metadata
                var metadata = new FileMetadata
                {
                    FileName = file.Name,
                    FilePath = file.FullName,
                    LastWriteTime = file.LastWriteTime,
                    FileSizeBytes = file.Length,
                    RecordsLoaded = recordsAdded,
                    LoadTimeMs = stopwatch.ElapsedMilliseconds
                };
                
                _loadedFiles.TryAdd(file.FullName, metadata);
                _totalRecordsLoaded += recordsAdded;
                _totalMemoryBytes += file.Length; // Rough estimate
                
                result.Success = true;
                result.RecordsLoaded = recordsAdded;
                result.LoadTimeMs = stopwatch.ElapsedMilliseconds;
                
                stopwatch.Stop();
                return result;
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
                return result;
            }
        }
        
        /// <summary>
        /// Load CSV file and return records as dictionaries
        /// Handles duplicate column names by appending _N suffix
        /// Handles multi-line fields (newlines inside quoted fields)
        /// </summary>
        private List<Dictionary<string, string>> LoadCsvFile(string filePath)
        {
            var records = new List<Dictionary<string, string>>();
            int skippedRecords = 0;
            
            using (var reader = new StreamReader(filePath, System.Text.Encoding.UTF8, detectEncodingFromByteOrderMarks: true))
            {
                // Read header (might span multiple lines if quoted)
                var headerLine = ReadCsvRecord(reader);
                if (string.IsNullOrWhiteSpace(headerLine))
                    return records;
                
                // Remove BOM if present
                if (headerLine.Length > 0 && headerLine[0] == '\uFEFF')
                {
                    headerLine = headerLine.Substring(1);
                }
                
                var rawHeaders = ParseCsvLine(headerLine);
                
                // Handle duplicate column names by appending _N suffix
                var headers = new string[rawHeaders.Length];
                var headerCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                
                for (int i = 0; i < rawHeaders.Length; i++)
                {
                    var header = rawHeaders[i].Trim();
                    
                    // Handle empty headers
                    if (string.IsNullOrWhiteSpace(header))
                    {
                        header = $"Column{i + 1}";
                    }
                    
                    // Check for duplicates
                    if (headerCounts.ContainsKey(header))
                    {
                        headerCounts[header]++;
                        headers[i] = $"{header}_{headerCounts[header]}";
                        Console.WriteLine($"[WARN] Duplicate column '{header}' renamed to '{headers[i]}'");
                    }
                    else
                    {
                        headerCounts[header] = 1;
                        headers[i] = header;
                    }
                }
                
                // Validate required columns
                var missingColumns = RequiredColumns.Where(col => 
                    !headers.Any(h => h.Equals(col, StringComparison.OrdinalIgnoreCase) || 
                                     h.StartsWith(col + "_", StringComparison.OrdinalIgnoreCase)))
                    .ToList();
                    
                if (missingColumns.Any())
                {
                    throw new InvalidDataException($"Missing required columns: {string.Join(", ", missingColumns)}");
                }
                
                // Read data rows (each might span multiple lines if quoted)
                int recordNumber = 1;
                string? line;
                while ((line = ReadCsvRecord(reader)) != null)
                {
                    recordNumber++;
                    
                    // Skip empty records
                    if (string.IsNullOrWhiteSpace(line))
                        continue;
                    
                    var values = ParseCsvLine(line);
                    
                    // Check if column count matches (with tolerance for trailing empty columns)
                    if (values.Length != headers.Length)
                    {
                        // Allow records that are close (missing only trailing empty columns)
                        if (values.Length < headers.Length && values.Length >= headers.Length - 10)
                        {
                            // Pad with empty strings
                            var paddedValues = new string[headers.Length];
                            Array.Copy(values, paddedValues, values.Length);
                            for (int i = values.Length; i < headers.Length; i++)
                            {
                                paddedValues[i] = "";
                            }
                            values = paddedValues;
                        }
                        else
                        {
                            // Significant mismatch - skip this record
                            skippedRecords++;
                            continue;
                        }
                    }
                    
                    var record = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    for (int i = 0; i < headers.Length && i < values.Length; i++)
                    {
                        // Use first occurrence of duplicate columns
                        var originalHeader = rawHeaders[i].Trim();
                        if (string.IsNullOrWhiteSpace(originalHeader))
                        {
                            originalHeader = $"Column{i + 1}";
                        }
                        
                        // Only add if not already present (prioritize first occurrence)
                        if (!record.ContainsKey(originalHeader))
                        {
                            record[originalHeader] = values[i]?.Trim() ?? "";
                        }
                    }
                    
                    records.Add(record);
                }
                
                if (skippedRecords > 0)
                {
                    Console.WriteLine($"[INFO] Skipped {skippedRecords} records due to column count mismatch");
                }
            }
            
            return records;
        }
        
        /// <summary>
        /// Read a complete CSV record, which might span multiple lines if it contains quoted newlines
        /// </summary>
        private string ReadCsvRecord(StreamReader reader)
        {
            var record = new System.Text.StringBuilder();
            var inQuotes = false;
            var line = reader.ReadLine();
            
            if (line == null)
                return null;
            
            record.Append(line);
            
            // Count quotes to determine if we're inside a quoted field
            foreach (var ch in line)
            {
                if (ch == '"')
                    inQuotes = !inQuotes;
            }
            
            // If we ended inside quotes, keep reading lines until we close the quote
            while (inQuotes && !reader.EndOfStream)
            {
                var nextLine = reader.ReadLine();
                if (nextLine == null)
                    break;
                
                // Preserve the newline that was consumed by ReadLine()
                record.Append('\n');
                record.Append(nextLine);
                
                // Update quote state
                foreach (var ch in nextLine)
                {
                    if (ch == '"')
                        inQuotes = !inQuotes;
                }
            }
            
            return record.ToString();
        }
        
        /// <summary>
        /// Load XLSX file and return records as dictionaries
        /// </summary>
        private List<Dictionary<string, string>> LoadXlsxFile(string filePath)
        {
            var records = new List<Dictionary<string, string>>();
            
            using (var package = new ExcelPackage(new FileInfo(filePath)))
            {
                var worksheet = package.Workbook.Worksheets[0];
                if (worksheet.Dimension == null)
                    return records;
                
                var rowCount = worksheet.Dimension.End.Row;
                var colCount = worksheet.Dimension.End.Column;
                
                // Read headers from first row
                var headers = new string[colCount];
                var headerCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                
                for (int col = 1; col <= colCount; col++)
                {
                    var cellValue = worksheet.Cells[1, col].Value?.ToString() ?? $"Column{col}";
                    
                    // Handle duplicate headers
                    if (headerCounts.ContainsKey(cellValue))
                    {
                        headerCounts[cellValue]++;
                        headers[col - 1] = $"{cellValue}_{headerCounts[cellValue]}";
                    }
                    else
                    {
                        headerCounts[cellValue] = 1;
                        headers[col - 1] = cellValue;
                    }
                }
                
                // Validate required columns (check base names for duplicates)
                var baseHeaders = headers.Select(h => h.Split('_')[0]).ToList();
                var missingColumns = RequiredColumns.Where(col => !baseHeaders.Contains(col, StringComparer.OrdinalIgnoreCase)).ToList();
                if (missingColumns.Any())
                {
                    throw new InvalidDataException($"Missing required columns: {string.Join(", ", missingColumns)}");
                }
                
                // Read data rows
                for (int row = 2; row <= rowCount; row++)
                {
                    var record = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    
                    for (int col = 1; col <= colCount; col++)
                    {
                        var cellValue = worksheet.Cells[row, col].Value?.ToString() ?? "";
                        record[headers[col - 1]] = cellValue;
                    }
                    
                    records.Add(record);
                }
            }
            
            return records;
        }
        
        /// <summary>
        /// Parse CSV line handling quotes, commas, and escaped quotes properly
        /// Handles RFC 4180 CSV format including:
        /// - Quoted fields with commas
        /// - Escaped quotes ("" becomes ")
        /// - Whitespace preservation in quoted fields
        /// </summary>
        private string[] ParseCsvLine(string line)
        {
            var values = new List<string>();
            var currentValue = new System.Text.StringBuilder();
            var inQuotes = false;
            
            for (int i = 0; i < line.Length; i++)
            {
                var ch = line[i];
                
                if (ch == '"')
                {
                    if (inQuotes)
                    {
                        // Check if this is an escaped quote (doubled quote)
                        if (i + 1 < line.Length && line[i + 1] == '"')
                        {
                            // Escaped quote - add single quote to value
                            currentValue.Append('"');
                            i++; // Skip the next quote
                        }
                        else
                        {
                            // End of quoted field
                            inQuotes = false;
                        }
                    }
                    else
                    {
                        // Start of quoted field
                        inQuotes = true;
                    }
                }
                else if (ch == ',' && !inQuotes)
                {
                    // End of field
                    values.Add(currentValue.ToString());
                    currentValue.Clear();
                }
                else
                {
                    // Regular character
                    currentValue.Append(ch);
                }
            }
            
            // Add the last field
            values.Add(currentValue.ToString());
            
            return values.ToArray();
        }
        
        /// <summary>
        /// Normalize MAC address to uppercase without delimiters
        /// </summary>
        private string NormalizeMacAddress(string macAddress)
        {
            return macAddress.Replace(":", "").Replace("-", "").Replace(".", "").ToUpper();
        }
        
        #endregion
        
        #region IDisposable
        
        public void Dispose()
        {
            if (!_disposed)
            {
                ClearCache();
                _disposed = true;
            }
            GC.SuppressFinalize(this);
        }
        
        #endregion
    }
    
    #region Supporting Classes
    
    /// <summary>
    /// Represents a Forescout host record
    /// </summary>
    public class ForescoutRecord
    {
        public string Host { get; set; } = "";
        public string IPv4Address { get; set; } = "";
        public string Segment { get; set; } = "";
        public string AccessIP { get; set; } = "";
        public string MacAddress { get; set; } = "";
        public string SwitchHostname { get; set; } = "";
        public string SwitchIPFQDNAndPortName { get; set; } = "";
        public string SwitchIPFQDN { get; set; } = "";
        public string SwitchPortName { get; set; } = "";
        public string SwitchPortAlias { get; set; } = "";
        public string SwitchPortVLAN { get; set; } = "";
        public string SwitchPortVLANName { get; set; } = "";
        public string SourceFilePath { get; set; } = "";
        public string SourceFileName { get; set; } = "";
        
        // Additional printer/network identification columns
        public string NICVendor { get; set; } = "";
        public string NICVendorValue { get; set; } = "";
        public string SensorSideIPv4 { get; set; } = "";
        public string QfabricEndpointMac { get; set; } = "";
        public string QfabricEndpointMacTroubleshooting { get; set; } = "";
        public string SwitchPortACL { get; set; } = "";
        public string SwitchPortACLTroubleshooting { get; set; } = "";
        public string SwitchPortAliasTroubleshooting { get; set; } = "";
    }
    
    /// <summary>
    /// Result of a MAC address search
    /// </summary>
    public class SearchResult
    {
        public ForescoutRecord? Record { get; set; }
        public bool Found { get; set; }
        public long SearchTimeMs { get; set; }
        public int FilesSearched { get; set; }
        public bool WasInCache { get; set; }
        public string Status { get; set; } = "";
    }
    
    /// <summary>
    /// Cache status information
    /// </summary>
    public class CacheStatus
    {
        public int TotalMacAddresses { get; set; }
        public int FilesLoaded { get; set; }
        public long TotalRecordsLoaded { get; set; }
        public double EstimatedMemoryMB { get; set; }
        public double MemoryPressurePercent { get; set; }
        public int CurrentFileIndex { get; set; }
        public int TotalFilesAvailable { get; set; }
        public bool IsMemoryPressureHigh { get; set; }
        public List<string> LoadedFileNames { get; set; } = new List<string>();
    }
    
    /// <summary>
    /// Result of file loading operation
    /// </summary>
    public class FileLoadResult
    {
        public string FileName { get; set; } = "";
        public bool Success { get; set; }
        public int RecordsLoaded { get; set; }
        public long LoadTimeMs { get; set; }
        public string ErrorMessage { get; set; } = "";
    }
    
    /// <summary>
    /// Result of preload operation
    /// </summary>
    public class PreloadResult
    {
        public int FilesLoaded { get; set; }
        public int FilesFailed { get; set; }
        public long RecordsLoaded { get; set; }
        public long LoadTimeMs { get; set; }
        public List<string> Errors { get; set; } = new List<string>();
        public CacheStatus? Status { get; set; }
    }
    
    /// <summary>
    /// Metadata about a loaded file
    /// </summary>
    public class FileMetadata
    {
        public string FileName { get; set; } = "";
        public string FilePath { get; set; } = "";
        public DateTime LastWriteTime { get; set; }
        public long FileSizeBytes { get; set; }
        public int RecordsLoaded { get; set; }
        public long LoadTimeMs { get; set; }
    }
    
    #endregion

#if NETFRAMEWORK
    /// <summary>
    /// Extension methods for .NET Framework compatibility
    /// Provides GetValueOrDefault which is not available in .NET Framework
    /// </summary>
    internal static class DictionaryExtensions
    {
        public static TValue GetValueOrDefault<TKey, TValue>(
            this IDictionary<TKey, TValue> dict, TKey key, TValue defaultValue)
        {
            if (dict == null) return defaultValue;
            return dict.TryGetValue(key, out var value) ? value : defaultValue;
        }

        public static TValue GetValueOrDefault<TKey, TValue>(
            this Dictionary<TKey, TValue> dict, TKey key, TValue defaultValue)
        {
            if (dict == null) return defaultValue;
            return dict.TryGetValue(key, out var value) ? value : defaultValue;
        }
    }
#endif
}
