# Active Directory Password Auditor

This project is a Python-based Active Directory password auditor that parses NTDS dumps, Hashcat potfiles, BloodHound JSON exports, and password policy files. It utilizes an on-disk SQLite database, multiprocessing for scalable data ingestion, and a Flask-based dynamic web portal for reporting.

## Usage

### 1. Extracting NTDS using `ntdsutil`
To pull the hashes from a domain controller, you can use the built-in `ntdsutil` tool. Run the following commands from an elevated command prompt on the domain controller:

```cmd
ntdsutil
activate instance ntds
ifm
create full C:\temp\ntds_export
quit
quit
```

This will export the Active Directory database (ntds.dit) and the SYSTEM registry hive to `C:\temp\ntds_export`.

### 2. Extracting Hashes with `secretsdump.py`
Once you have the `ntds.dit` and `SYSTEM` hive, you need to extract the hashes. You can use `secretsdump.py` from Impacket to do this. Be sure to include the `-history` flag to extract password history, which this tool supports analyzing.

```bash
secretsdump.py -ntds "C:\temp\ntds_export\Active Directory\ntds.dit" -system C:\temp\ntds_export\registry\SYSTEM LOCAL -history -outputfile extracted_hashes
```
This will produce a file named `extracted_hashes.ntds` containing the user hashes.

### 3. Cracking Hashes
You will need to crack the extracted hashes using a tool like Hashcat. This tool expects a standard Hashcat potfile.

```bash
hashcat -m 1000 extracted_hashes.ntds wordlist.txt
```
This will produce a `hashcat.potfile` with the cracked passwords.

### 4. Running the Analyzer
The primary script for ingestion is `analyze_hashes.py`. It requires the NTDS file and the Hashcat potfile. You can also optionally include Bloodhound data, password policy rules, and high-value target definitions.

**Basic Example:**
```bash
python analyze_hashes.py --ntds extracted_hashes.ntds --potfile hashcat.potfile
```

**Advanced Example with BloodHound and Policy:**
```bash
python analyze_hashes.py \
    --ntds extracted_hashes.ntds \
    --potfile hashcat.potfile \
    --bloodhound bloodhound_users.json bloodhound_groups.json \
    --policy example_policy.json \
    --high-value example_high_value_groups.txt \
    --redact
```
*Note: The `--redact` flag will redact the cracked passwords in the database and web reports.*

**Using the Example Files:**
- `example_policy.json`: A sample password policy definition. You can modify it to match your organization's required base password length/complexity, and define Fine-Grained Password Policies (FGPP) for specific groups (e.g., Domain Admins). Pass this file with the `--policy` flag to calculate policy violations.
- `example_high_value_groups.txt`: A sample list of high value groups (one per line). Pass this file with the `--high-value` flag to track and filter cracked accounts belonging to these groups in the web report.

### 5. Viewing the Reports
After `analyze_hashes.py` finishes, it will generate an SQLite database named `analysis.db`.
You can view the interactive reports using the Flask web portal.

Start the web server:
```bash
python app.py
```

Then, open your web browser and navigate to `http://127.0.0.1:5000` to view the dashboard and interact with the various reports (Lengths, Shared Passwords, History, Kerberoastable, etc.).
