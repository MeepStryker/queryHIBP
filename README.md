# queryHIBP
This project uses HaveIBeenPwned's (HIBP's) API to identify passwords captured from honeypots that have not been seen in breaches.

To download the project and try it out with some test data, one can run the following:
```git clone https://github.com/MeepStryker/queryHIBP.git; cd queryHIBP; python3 queryHIBP.py ./sampleInput.txt ./passwordResults.csv ./unseenPasswords.txt```

As the script runs, it will print out each unseen password identified. A short summary will be printed at the end listing how many passwords were processed, skipped, and have not been seen by HIBP.

Note that the password results CSV should include a header of "password,sha1,count" at the top.
