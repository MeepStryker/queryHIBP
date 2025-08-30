#!/usr/bin/env python3
"""
Usage:
  python3 queryHIBP.py INPUT RESULTS UNSEEN

INPUT   : file with one password per line.
RESULTS : CSV with results for all checked passwords (password,sha1,count). Used to avoid checking passwords repeatedly.
UNSEEN  : text file for passwords that HIBP has not seen.

- Skips passwords already present in RESULTS file
- Queries HIBP with first 5 chars (prefix) of SHA1 hash - https://api.pwnedpasswords.com/range/#####
- Appends count of each password (including 0 if unseen) to RESULTS file
- Appends plaintext of unseen passwords to UNSEEN file

https://github.com/MeepStryker/queryHIBP
"""

import csv # for reading results file
import hashlib # for hashing input passwords
import sys # to read command line arguments
import time # to sleep before retrying requests
import requests # to query HIBP API

# HIBP likes a descriptive user-agent to be specified when making API requests
# This can be changed as desired
HEADERS = {"User-Agent": "PasswordCheckingProject"}
TIMEOUT = 20
MAX_RETRIES = 3


def hash_password(password):
    # Return SHA1 hash of provided password
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

def fetch_range(prefix, session):
    # Returns a dictionary of suffixes mapped to the count, based on the results queried for a given 5-char prefix.


    # Format string for HIBP API; uses provided prefix
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    # Track the number of attempts made, default max retries is 3
    attempt = 0
    while True:
        try:
            # Query the HIBP API
            resp = session.get(url, headers=HEADERS, timeout=TIMEOUT)

            # If 429 code is returned,
            if resp.status_code == 429:
                attempt += 1
                # If there have been too many attempts, raise error to quit out
                # This will eventually raise an error right to the user and stop execution
                if attempt > MAX_RETRIES:
                    resp.raise_for_status()

                # Pull retry-after from headers and convert to int
                retry_after = int(resp.headers["Retry-After"])

                # Wait however many seconds HIBP told us to and continue
                time.sleep(retry_after)
                continue

            # Raises error if request was not successful
            resp.raise_for_status()

            # Store each line of the response in dictionary (stores suffix and how many times HIBP has seen the password)
            out = {}
            for line in resp.text.splitlines():
                if not line:
                    continue
                try:
                    suffix, count = line.split(":")
                    out[suffix.strip().upper()] = count.strip()
                except ValueError:
                    pass
            return out
        except requests.RequestException:
            attempt += 1
            if attempt > MAX_RETRIES:
                # Print error message with the queried prefix if the attempt limit was reached and stop execution/raise error
                print(f"Error while making request for prefix: {prefix}", file=sys.stderr)
                raise
            # Sleep for 5 seconds if there are more attempts remaining
            time.sleep(5)

def load_processed_plaintext(results_path):
    # Create a set to store the plaintext passwords that have been checked previously based on contents in provided filepath

    seen = set()
    # Open results as read only
    with open(results_path, "r", encoding="utf-8", newline="") as f:
        # Use csv.DictReader and check for password in the header/field names
        reader = csv.DictReader(f)
        if reader.fieldnames and "password" in reader.fieldnames:
            for row in reader:
                password = row.get("password")
                # Store whatever is in the password column for each row if it isn't empty
                if password is not None:
                    seen.add(password)
    # Return the set of passwords
    return seen

def main():
    # Check for proper number of arguments and print simple usage info if needed
    if len(sys.argv) != 4:
        print("Usage: python3 queryHIBP.py INPUT RESULTS UNSEEN", file=sys.stderr)
        sys.exit(1)

    # Save file paths for input/results/unseen from command line arguments
    input_path, results_path, unseen_path = sys.argv[1], sys.argv[2], sys.argv[3]

    # Save a set of all plaintext passwords that have been checked before in the results file
    processed = load_processed_plaintext(results_path)

    # Tracker variables for skipped, newly checked, and new unseen passwords. Final totals printed at the end.
    skipped = 0
    checked = 0
    new_unseen = 0

    session = requests.Session()

    # Dictionary to store prefixes and the associated results from HIBP as a dictionary
    # This allows us to avoid duplicate requests if different passwords happen to have the same prefix
    prefix_cache: dict[str, dict[str, str]] = {}  # prefix -> {suffix: count}

    # Open results, unseen, and input files
    # Results and unseen opened as append, input as read
    with open(results_path, "a", encoding="utf-8", newline="") as out_csv, open(unseen_path, "a", encoding="utf-8") as unseen_out, open(input_path, "r", encoding="utf-8", errors="surrogatepass") as password_list:

        # Use csv writer to handle output CSV for commas/quotes/newlines in passwords
        writer = csv.writer(out_csv)

        # For each line in the input file: pull out the password, check if it has been queried before, hash the password
        for line in password_list:

            # Strip newlines
            password = line.rstrip("\r\n")

            # If the password is empty, don't process
            if password == "":
                continue

            # Skip processed passwords and add to our counter for stats at the end
            if password in processed:
                skipped += 1
                continue

            # Hash password and store it
            sha1_password = hash_password(password)
            # Store hash as 5 character prefix for request and 35 character suffix for result matching
            prefix, suffix = sha1_password[:5], sha1_password[5:]

            # fetch or reuse the range for this prefix
            if prefix not in prefix_cache:
                # If prefix hasn't been queried for, use fetch_range to make query and store results in dictionary
                try:
                    prefix_cache[prefix] = fetch_range(prefix, session)
                except requests.RequestException as e:
                    # If fetch fails: print error message, set count to -1, and keep going
                    print(f"# fetch error for prefix {prefix}: {e}", file=sys.stderr)
                    count = -1
                else:
                    # If there are no errors, check the prefix cache for the suffix, set 0 if not there
                    count = int(prefix_cache[prefix].get(suffix, "0"))
            else:
                # Check the prefix cache for the suffix, set 0 if not there
                count = int(prefix_cache[prefix].get(suffix, "0"))

            if count != -1:
                # Append password, hash, and count to results file and update number of checked passwords if there was no error
                writer.writerow([password, sha1_password, count])
                checked += 1

            # Add password to processed set so duplicates in the input aren't checked again
            processed.add(password)

            # If we find a password not seen by HIBP: print it during execution, added a line to the unseen output file, and update stats
            if count == 0:
                print(f"Unseen password identified: {password}")
                unseen_out.write(password + "\n")
                new_unseen += 1

    # Print summary information
    print(f"Done!\nChecked {checked} new passwords.\nIdentified {new_unseen} new, unseen passwords.\nSkipped {skipped} previously checked passwords.")

if __name__ == "__main__":
    main()
