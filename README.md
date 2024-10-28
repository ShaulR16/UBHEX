# UBHEX

**UBHEX** (User Behavior Heuristic Examiner) is a PowerShell script designed to analyze user activity by aggregating data from multiple sources on a Windows machine.. This tool is particularly useful for red team, who aim to schedule activities during typical user active periods to blend in with normal behavior and avoid detection.

## About

UBHEX analyzes user activity by collecting and consolidating data from various sources, including:

1. **File Access and Modification Times**: Scans user directories to gather timestamps of file interactions.
2. **Browser Usage Metadata**: Extracts last modified times of browser history files (Chrome, Edge, Firefox).
3. **Scheduled Tasks Execution History**: Retrieves execution times of the user's scheduled tasks.
4. **Windows Event Logs**: Analyzes Logon/Logoff and Workstation Lock/Unlock events.
5. **Registry Analysis**: Examines recent documents and startup programs entries.
6. **Sync Folders Activity**: Monitors activity in sync folders like OneDrive, Dropbox, and Google Drive.

 ## Features

- **Comprehensive Activity Analysis**: Aggregates data from multiple sources for in-depth user activity profiling.
- **Adjustable Verbosity Levels**: Choose between 'Quiet' and 'Verbose' modes to control the level of output detail.
- **Security-Aware**: Checks for the presence of AV/EDR and adjusts behavior to minimize detection (low-profile mode).
- **Resource-Friendly**: Performs pre-run system load checks to avoid high resource usage and potential detection.
- **Customizable Analysis Period**: Analyzes user activity over a defined time range (default is 60 days).
- **Stealth Mode**: Enters low-profile mode when AV/EDR detected, reducing the script's footprint(By timing and sleeps).

  ## Prerequisites

- **Operating System**: Windows
- **PowerShell**: Version 5.0 or higher

  ## Usage

UBHEX is a PowerShell script that can be executed from the command line. Open a PowerShell window and navigate to the directory containing `UBHEX.ps1`.

```powershell
.\UBHEX.ps1 [-V Quiet|Verbose] [-Help]
```
### Parameters

- `-V`: Sets the verbosity level of the script output. Accepts `'Quiet'` or `'Verbose'`. Default is `'Quiet'`.
- `-Help`: Displays the help message and exits.

### Examples

- **Run the script in quiet mode (default):**

  ```powershell
  .\UBHEX.ps1
  ```
  
- **Run the script in verbose mode to see detailed output:**

  ```powershell
  .\UBHEX.ps1 -V Verbose
  ```

- **Display the help message:**

  ```powershell
  .\UBHEX.ps1 -Help
  ```

## Output

The script generates a consolidated summary of user activity, including:

- **Overall Activity Period**: The earliest and latest activity timestamps within the analyzed period.
- **Total Active Days**: Number of days the user was active.
- **Maximum Consecutive Active Days**: The longest streak of consecutive active days.
- **Average Operating Times per Day**: For each day of the week, displays:
  - Average operating duration.
  - Average activity start and end times.
  - Number of days active on that day.

### Sample Output

```
--- User's Average Operating Times per Day ---
 - Monday: Average Operating Duration: 08:30 hours over 8 day(s)
   Average Activity Hours: 08:15 - 16:45
 - Tuesday: Average Operating Duration: 08:45 hours over 9 day(s)
   Average Activity Hours: 08:00 - 16:45
...

Conclusion:
Over the analyzed period, the user's average daily active time is approximately 08:37 hours (excluding locked periods).

UBHEX analysis completed.
```
## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
