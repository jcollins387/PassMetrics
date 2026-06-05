# Active Directory Password Auditor

This project is a Python-based Active Directory password auditor that parses NTDS dumps, Hashcat potfiles, BloodHound JSON exports, and password policy files. It utilizes an on-disk SQLite database, multiprocessing for scalable data ingestion, and a Flask-based dynamic web portal for reporting.

## Usage

### 1. Extracting NTDS using `ntdsutil`
To pull the hashes from a domain controller, you can use the built-in `ntdsutil` tool. Run the following commands from an elevated command prompt on the domain controller:

```cmd
ntdsutil activate instance ntds ifm create full C:\temp\ntds_export quit quit
```

This will export the Active Directory database (ntds.dit) and the SYSTEM registry hive to `C:\temp\ntds_export`.

### 2. Extracting Hashes with `secretsdump.py`
Once you have the `ntds.dit` and `SYSTEM` hive, you need to extract the hashes. You can use `secretsdump.py` from Impacket to do this. Be sure to include the `-history` flag to extract password history, which this tool supports analyzing.

```bash
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL -history -outputfile extracted_hashes
```
This will produce a file named `extracted_hashes.ntds` containing the user hashes.

### 3. Cracking Hashes
You will need to crack the extracted hashes using a tool like Hashcat. This tool expects a standard Hashcat potfile.

```bash
hashcat -m 1000 extracted_hashes.ntds wordlist.txt
```
This will produce a `hashcat.potfile` with the cracked passwords.

### 4. Running the Analyzer
The primary script for ingestion is `adpa.py`. It requires the NTDS file and the Hashcat potfile. You can also optionally include Bloodhound data, password policy rules, and high-value target definitions.

**Basic Example:**
```bash
python adpa.py --ntds extracted_hashes.ntds --potfile hashcat.potfile
```

**Advanced Example with BloodHound, Policy, and Domain Mappings:**
```bash
python adpa.py \
    --ntds extracted_hashes.ntds \
    --potfile hashcat.potfile \
    --bloodhound bloodhound_users.json bloodhound_groups.json \
    --policy example_policy.json \
    --high-value example_high_value_groups.txt \
    --domain-mapping mapping.json \
    --interactive \
    --redact
```
*Note: The `--redact` flag will redact the cracked passwords in the database and web reports.*

**Domain Mapping (`--domain-mapping` & `--interactive`):**
Sometimes the domain names in the NTDS dump differ from the domain names found in BloodHound exports (e.g. short NetBIOS names versus FQDNs). You can provide a JSON file via `--domain-mapping` to map NTDS domain names to one or more BloodHound target domains.
* **Format:** The file should contain a dictionary mapping original NTDS domains to lists of possible BloodHound domains:
  ```json
  {
    "SHORTDOM": ["fqdn1.local", "corp.fqdn1.local"],
    "OTHERDOM": ["other.local"]
  }
  ```
* **Automatic Resolution:** If a domain has a 1-to-many mapping, the tool will attempt to automatically resolve the ambiguity by checking if any of the target domains for that user explicitly appear elsewhere in the NTDS data.
* **Interactive Mode:** If you pass the `--interactive` flag, any mapping ambiguity that cannot be automatically resolved will prompt the user in the CLI to manually select the correct domain for each affected account.
* **GUI Resolution:** Alternatively, you can run the web app and use the "Domain Mappings" tab to manually correct any misaligned domains after the initial data ingestion is complete.

**Using the Example Files:**
- `example_policy.json`: A sample password policy definition. You can modify it to match your organization's required base password length/complexity, and define Fine-Grained Password Policies (FGPP) for specific groups (e.g., Domain Admins), OUs, or username patterns (e.g., service accounts).
  - **Policy Names:** The base policy and individual fine-grained password policies require a `"name"` field. This policy name is saved to the database and displayed in a dedicated column on the 'Policy Violations' report page to indicate which policy was tested against the account.
  - **Matching Logic:** The script evaluates the base policy against all accounts. It then evaluates all policies defined in the `fgpp` dictionary. For each FGPP policy, an account is a match if it meets *any* of the following conditions:
    - `match_groups`: The account is a member of a group that matches exactly (case-insensitive).
    - `match_ous`: The account's Distinguished Name (DN) contains a string from this list as a substring (case-insensitive).
    - `match_usernames`: The account's username matches a regular expression defined in this list.
  - **Multiple Match Logic (Most Restrictive):** If an account matches multiple FGPP rules (e.g., it is in "Domain Admins" and its username starts with "svc-"), the script will generate a composite policy applying the most restrictive settings from all matched policies (highest minimum length, true if any require complexity, and lowest maximum lifetime).
- `example_high_value_groups.txt`: A sample list of high value groups (one per line). Pass this file with the `--high-value` flag to track and filter cracked accounts belonging to these groups in the web report.
  - **Matching Logic:** The script performs an exact, case-insensitive match against the group name. It is not a fuzzy match. For example, "Admin" will not match "Domain Admins". A user must be explicitly listed as a member of the exact group name provided in this file to be considered a high-value target.

### 5. Viewing the Reports
After `adpa.py` finishes, it will generate an SQLite database named `analysis.db`.
You can view the interactive reports using the Flask web portal.

**Administrator Credentials:**
On the first run, `adpa.py` will create an `Administrator` account for the web portal.
* If run interactively, it will prompt you to set the initial password.
* If run non-interactively, a secure random password will be generated and saved to `admin_credentials.txt` with strict (`0o600`) permissions.

Start the web server:
```bash
python app.py
```

Then, open your web browser and navigate to `http://127.0.0.1:5000` to view the dashboard and interact with the various reports (Lengths, Shared Passwords, History, Kerberoastable, etc.).
