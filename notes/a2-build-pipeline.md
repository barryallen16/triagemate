# A2: pinned Vul4J build pipeline

## What this proves

Seven target-CWE Vul4J entries build from a clean clone with OpenJDK 8 and Maven 3.9.12.
The A1 audit found 14 buildable target-CWE entries.
This note re-runs the build path with the pinned toolchain on the current VPS.
It does not rebuild all 14.

## Pinned toolchain

- OpenJDK 8u504 at `/usr/lib/jvm/java-8-openjdk-amd64`
- Apache Maven 3.9.12 at `/opt/apache-maven-3.9.12`
- Python 3.12, no project dependencies for the audit script
- Semgrep 1.182.1 for the A3 scans

The audit script runs one repository at a time and deletes the checkout after the build.
That keeps peak disk use bounded on the 32 GB VPS.

## Command

```bash
export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
export PATH=/opt/apache-maven-3.9.12/bin:$JAVA_HOME/bin:$PATH
export MAVEN_OPTS='-Xmx448m'
python3 scripts/vul4j-audit/audit_builds.py 0 \
  --ids VUL4J-25,VUL4J-41,VUL4J-42,VUL4J-47,VUL4J-59,VUL4J-60,VUL4J-79 \
  --report data/vul4j-audit/builds-pinned.jsonl
```

The script also accepts `--force` to rebuild IDs already in the report.
`--report` writes to a separate file so the A1 audit report stays intact.

## Results

| Entry | CWE | Java version | Build |
|---|---|---|---|
| VUL4J-25 | CWE-79 | not declared | OK |
| VUL4J-41 | CWE-22 | not declared | OK |
| VUL4J-42 | CWE-78 | not declared | OK |
| VUL4J-47 | CWE-611 | not declared | OK |
| VUL4J-59 | CWE-79 | 1.5 | OK |
| VUL4J-60 | CWE-79 | not declared | OK |
| VUL4J-79 | CWE-22 | 1.6 | OK |

VUL4J-25 and VUL4J-79 failed once during a batch run on the 1 GB VPS, then passed when rerun alone.
The report keeps the passing result.
Build one memory-heavy entry at a time on this host.

All seven entries use Java 1.5 to 1.8 source.
No entry needs JDK 11 or newer.
JDK 8 plus Maven 3.9 covers every buildable entry found in A1.

## Next

A3 scans the buildable entries with Semgrep 1.182.1 and labels the findings from the patch commit.
