# DPSAnalyzer

Tbh i see https://github.com/nay-cat/dpsanalyzer and I said, why not read the DPS memory directly instead of using System Informer and dumping it manually?!

---

## How It Works

DPSAnalyzer performs a full memory scan of the DPS service and extracts all printable strings from its memory space. From this raw memory data, the tool applies multiple filtering, correlation, and post-processing stages to generate structured and meaningful output files.

The analysis includes:

* Full DPS memory string extraction
* Duplicate entry detection
* Executable path extraction (`.exe`)
* Filtering of structured DPS entries (`!!`)
* Device path to drive letter conversion (e.g. `\\Device\\HarddiskVolumeX\\` → `C:\\`)
* Digital signature verification, detection of signed, unsigned, locally signed, or fake-signed executables
* File existence checks
* Automatic result generation (no manual arguments required)

All results are saved automatically as text files.

---

## Output Files

### `dps_strings.txt`

Contains **all strings (MAJOR 5 characters)** extracted from the DPS memory space. This file represents the raw memory dump in string form and serves as the base for all subsequent analysis.

---

### `dps-query-results.txt`

Filters and contains all entries that:

* Start with `!!`
* Contain `.exe`

These entries usually represent structured or internally flagged execution traces inside DPS.

---

### `dps-suspicious-results.txt`

Look in **dps-query-results.txt** and filters **duplicated entries** founds.

---

### `dps-parsed-results.txt`

Filters all `.exe` paths extracted from DPS memory.

This includes:

* Extracting valid executable paths
* Converting device paths (e.g. `\\Device\\HarddiskVolumeX\\`) to normal paths (e.g. `C:\\`)

Only normalized and valid executable paths are included.

---

### `dps-parsed-paths.txt`

Searches executable paths based on the results from `dps-suspicious-results.txt` and correlates them with:

* Resolved executable paths
* Digital signature information

This file links suspicious duplicated entries with their corresponding executables and signature status.

---

### `dps-full-unsigned-executables.txt`

Filters and contains all executable paths that are:

* Unsigned
* Locally signed (LocalSign)
* Fake signed or invalidly signed

Tbh these executables should be carefully reviewed, as they often indicate malicious, tampered, or untrusted binaries... but is DPS so yeah!!

---

### `dps-full-sigcheck-executables.txt`

Filters and contains all executable paths along with their **corresponding digital signature information**.

---

### `dps-full-notfound-executables.txt`

Filters and contains all executable paths that:

* Were referenced in DPS memory
* Could not be found on disk at analysis time

This often indicates deleted, moved, etc.
