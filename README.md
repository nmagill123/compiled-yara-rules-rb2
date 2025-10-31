# Compiled YARA Rules

Automated compilation and distribution of YARA rules from [Elastic's protections-artifacts repository](https://github.com/elastic/protections-artifacts) with support for custom rules.

## Features

- 🔄 **Automated Updates**: Pulls latest YARA rules from Elastic's repository
- 📦 **Platform-Specific Packages**: Separate archives for Linux and Windows
- 🎯 **Custom Rules Support**: Add your own YARA rules via the `custom/` directory
- 🚀 **GitHub Actions Integration**: Automatic builds and releases
- 📅 **Scheduled Updates**: Weekly automatic updates (configurable)

## Release Artifacts

Each release contains two compressed archives:

### `linux.tar.xz`
Contains all YARA rules for Linux systems:
- Rules prefixed with `Linux_*`
- Rules prefixed with `Multi_*` (cross-platform)
- Custom rules following the same naming convention

### `windows.tar.xz`
Contains all YARA rules for Windows systems:
- Rules prefixed with `Windows_*`
- Rules prefixed with `Multi_*` (cross-platform)
- Custom rules following the same naming convention

## Usage

### Download and Extract

```bash
# Download the latest release
wget https://github.com/YOUR_USERNAME/YOUR_REPO/releases/latest/download/linux.tar.xz
wget https://github.com/YOUR_USERNAME/YOUR_REPO/releases/latest/download/windows.tar.xz

# Extract Linux rules
mkdir -p /opt/yara/rules/linux
tar -xJf linux.tar.xz -C /opt/yara/rules/linux/

# Extract Windows rules (on Windows or via WSL)
mkdir -p /opt/yara/rules/windows
tar -xJf windows.tar.xz -C /opt/yara/rules/windows/
```

### Scan with YARA

```bash
# Scan a directory with Linux rules
yara -r /opt/yara/rules/linux/ /path/to/scan/

# Scan a specific file
yara /opt/yara/rules/linux/Linux_Trojan_Generic.yar /path/to/suspicious/file

# Scan with all rules recursively
find /opt/yara/rules/linux/ -name "*.yar" -exec yara {} /path/to/scan/ \;
```

## Adding Custom Rules

1. Create your YARA rule files in the `custom/` directory
2. Follow the naming convention:
   - `Linux_*.yar` for Linux-specific rules
   - `Windows_*.yar` for Windows-specific rules
   - `Multi_*.yar` for cross-platform rules
3. Commit and push to trigger a new build

Example custom rule:

```yara
rule Linux_Custom_Malware_Detection
{
    meta:
        description = "Detects custom malware pattern"
        author = "Security Team"
        date = "2025-10-31"
        
    strings:
        $magic = { 4D 5A 90 00 }
        $string1 = "malicious_pattern" ascii wide
        
    condition:
        $magic at 0 and $string1
}
```

See [custom/README.md](custom/README.md) for more details.

## Triggering Builds

The workflow can be triggered in three ways:

### 1. Manual Trigger
Navigate to Actions → Build and Release YARA Rules → Run workflow

### 2. Tag-Based Release
```bash
git tag v1.0.0
git push origin v1.0.0
```

### 3. Scheduled (Automatic)
The workflow runs automatically every Monday at 00:00 UTC to pull the latest rules from Elastic's repository.

## Workflow Configuration

The GitHub Actions workflow is located at `.github/workflows/build-yara-rules.yml`.

### Customize Schedule

To change the update frequency, modify the cron expression:

```yaml
schedule:
  - cron: '0 0 * * 1'  # Every Monday at midnight UTC
```

Common cron patterns:
- `0 0 * * *` - Daily at midnight
- `0 0 * * 0` - Weekly on Sunday
- `0 0 1 * *` - Monthly on the 1st

### Environment Requirements

The workflow requires:
- GitHub Actions enabled
- `GITHUB_TOKEN` (automatically provided)
- Write permissions for releases

## Rule Sources

### Elastic Protections Artifacts
Primary source: https://github.com/elastic/protections-artifacts/tree/main/yara

Rules cover various threat categories:
- Backdoors
- Trojans
- Ransomware
- Cryptominers
- Webshells
- Exploits
- Infostealers
- And more...

### Rule Categories by Prefix

| Prefix | Platform | Description |
|--------|----------|-------------|
| `Linux_*` | Linux | Linux-specific malware |
| `Windows_*` | Windows | Windows-specific malware |
| `MacOS_*` | macOS | macOS-specific malware (not included in current archives) |
| `Multi_*` | Cross-platform | Platform-agnostic rules |

## Advanced Usage

### Integration with Security Tools

#### YARA Scanner Service

```bash
#!/bin/bash
RULES_DIR="/opt/yara/rules/linux"
SCAN_DIR="/var/www"
LOG_FILE="/var/log/yara-scan.log"

yara -r -w -m "$RULES_DIR" "$SCAN_DIR" >> "$LOG_FILE" 2>&1
```

#### Scheduled Scanning (cron)

```bash
# Add to crontab: scan every 6 hours
0 */6 * * * /usr/local/bin/yara-scan.sh
```

#### Integration with OSSEC/Wazuh

```xml
<localfile>
    <log_format>syslog</log_format>
    <location>/var/log/yara-scan.log</location>
</localfile>
```

## Contributing

1. Fork the repository
2. Add your custom rules to the `custom/` directory
3. Test your rules locally
4. Submit a pull request

## License

- **This repository**: MIT License (or your chosen license)
- **Elastic YARA Rules**: See [Elastic's license](https://github.com/elastic/protections-artifacts/blob/main/LICENSE.txt)

## Security Notice

⚠️ **Important**: YARA rules may trigger false positives. Always:
- Test rules in a controlled environment
- Review detected files manually
- Keep rules updated regularly
- Maintain a whitelist for known false positives

## Support

For issues with:
- **This workflow**: Open an issue in this repository
- **Elastic's YARA rules**: See [elastic/protections-artifacts](https://github.com/elastic/protections-artifacts)
- **YARA itself**: See [VirusTotal/yara](https://github.com/VirusTotal/yara)

## Resources

- [YARA Documentation](https://yara.readthedocs.io/)
- [Writing YARA Rules Guide](https://yara.readthedocs.io/en/stable/writingrules.html)
- [Elastic Security Labs](https://www.elastic.co/security-labs)
- [YARA Exchange](https://github.com/InQuest/awesome-yara)

---

**Last Updated**: October 31, 2025
