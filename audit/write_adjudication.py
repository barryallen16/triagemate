"""Write the manual adjudication of the 64-row sample.

Verdicts:
  real      the flagged sink is the vulnerability the fix patch addresses
  partial   same method or sink, but the patch fixes a different weakness
            or disables the endpoint without fixing the sink
  not-real  the patch does not touch the flagged construct, or the finding
            is unrelated to the advisory
"""

import json
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent

# (verdict, reason) in packet order.
VERDICTS = [
    ("real", "fix commit adds safe parser configuration and external-access restrictions to the XMLHelper factories, covering the flagged getDocBuilder path"),
    ("real", "patch routes XML without a system ID through EmptyEntityResolver, blocking external entities at the flagged factory"),
    ("real", "patch escapes EL expressions in addViolation before building the constraint message"),
    ("real", "patch disables DOCTYPE, external entities and external DTDs on the MSTest report parser factory"),
    ("real", "patch hardens getDocumentBuilder with DOCTYPE, entity and external DTD restrictions"),
    ("real", "patch sets accessExternalDTD and accessExternalStylesheet to empty on the XSLT transformer factory"),
    ("real", "patch sets accessExternalDTD and accessExternalStylesheet to empty on the XSLT transformer factory"),
    ("real", "patch adds enableOrDisableExternalEntityParsing and applies it to the builder factory in createDocumentImpl"),
    ("real", "patch adds enableOrDisableExternalEntityParsing and applies it to the builder factory in parseDocumentImpl"),
    ("partial", "patch enables FEATURE_SECURE_PROCESSING on the transformer factory but leaves external DTD and stylesheet access enabled, so the flagged XXE pattern is only partly mitigated"),
    ("partial", "patch enables FEATURE_SECURE_PROCESSING on the transformer factory but leaves external DTD and stylesheet access enabled, so the flagged XXE pattern is only partly mitigated"),
    ("not-real", "patch does not touch the DocumentBuilderFactory created inside transform; only the transformer factory is changed"),
    ("real", "patch replaces ObjectInputStream with the configured pac4j Serializer"),
    ("real", "patch adds an expression-language feature level that can disable bean and method resolution"),
    ("real", "patch replaces the factory with XMLUtil.newXXEProtectedDocumentBuilderFactory"),
    ("real", "patch replaces the factory with XMLUtil.newXXEProtectedDocumentBuilderFactory"),
    ("real", "patch replaces the factory with XMLUtil.newXXEProtectedDocumentBuilderFactory"),
    ("real", "patch switches the script engine to Nashorn with --no-java, blocking Java class access"),
    ("real", "patch switches the script engine to Nashorn with --no-java, blocking Java class access"),
    ("not-real", "patch only reorders upload handling; the MD5 digest in the flagged method is unchanged"),
    ("not-real", "patch adds a FlippingStrategy type check for the RCE advisory; the flagged log statement is unchanged"),
    ("partial", "patch removes the user-controlled executorAddress and fixes the SSRF, but the flagged request mapping still allows all HTTP methods"),
    ("real", "patch rejects callerUrl values outside the servlet context path before the redirect"),
    ("not-real", "patch only guards the redirect target; the flagged session attributes still take request parameters"),
    ("not-real", "patch only guards the redirect target; the flagged session attributes still take request parameters"),
    ("real", "patch disables DOCTYPE, XInclude and entity expansion on the flagged region-metadata factory"),
    ("not-real", "patch is a path-traversal fix in UnpackerBase and does not change the deserialization calls"),
    ("not-real", "patch is a path-traversal fix in UnpackerBase and does not change the deserialization calls"),
    ("real", "patch adds canonical-path containment checks in getRequestedFile"),
    ("real", "patch adds canonical-path containment checks in getRequestedFile"),
    ("real", "patch adds canonical-path containment checks in getRequestedFile"),
    ("not-real", "the flagged directory-list loop operates on a file already built from the servlet root; the patch hardens the File constructors, not this sink"),
    ("real", "patch sets accessExternalDTD and accessExternalStylesheet to empty on the XMP transformer factory"),
    ("real", "patch sets disallow-doctype-decl and disables XInclude and entity expansion on the response parser factory"),
    ("real", "patch adds secureDocumentBuilderFactory and calls it on the flagged factory"),
    ("real", "patch sets disallow-doctype-decl and disables external general entities on the version parser factory"),
    ("real", "patch installs an entity resolver that serves only classpath entities, blocking external resolution"),
    ("real", "patch installs an entity resolver that serves only classpath entities, blocking external resolution"),
    ("real", "patch installs an entity resolver that serves only classpath entities, blocking external resolution"),
    ("not-real", "patch adds an inline-versus-attachment XSS policy; the flagged DefaultHttpClient remains"),
    ("real", "patch installs an ObjectInputFilter allowlist on the Connector stream"),
    ("not-real", "patch adds authentication and host binding but keeps the plaintext ServerSocket; no TLS is added"),
    ("real", "patch enables FEATURE_SECURE_PROCESSING on the FOP transformer factory, the fix for the advisory's XXE"),
    ("real", "patch enables FEATURE_SECURE_PROCESSING on the FOP transformer factory, the fix for the advisory's XXE"),
    ("real", "patch adds a resolveClass allowlist to the Raft message decoder"),
    ("real", "patch sets disallow-doctype-decl on the shared DocumentBuilderFactory in the Utils constructor"),
    ("real", "patch enables FEATURE_SECURE_PROCESSING on the XSL content transformer factory"),
    ("not-real", "patch is an SSRF/XSS fix that removes saveConfig and adds null checks; the flagged path is still built from request input without a containment check"),
    ("not-real", "patch is an SSRF/XSS fix that removes saveConfig and adds null checks; the flagged path is still built from request input without a containment check"),
    ("not-real", "patch does not add a canonical-path check to getRequestedFile; the flagged File construction is unchanged"),
    ("not-real", "patch does not add a canonical-path check to getRequestedFile; the flagged File construction is unchanged"),
    ("not-real", "patch does not add a canonical-path check to getRequestedFile; the flagged File construction is unchanged"),
    ("not-real", "patch does not harden the processStaticRequest file path; the flagged construction remains"),
    ("not-real", "patch does not harden the processStaticRequest file path; the flagged construction remains"),
    ("not-real", "patch does not harden the processStaticRequest file path; the flagged construction remains"),
    ("not-real", "patch does not harden the processStaticRequest file path; the flagged construction remains"),
    ("partial", "patch removes the saveConfig call from doPost, disabling the endpoint, but does not sanitize the path inside saveConfig"),
    ("partial", "patch removes the saveConfig call from doPost, disabling the endpoint, but does not sanitize the path inside saveConfig"),
    ("real", "patch applies DOCTYPE, external entity, external DTD and XInclude restrictions to the XA result parser factory"),
    ("real", "patch installs a Subject deserialization filter and hardens the custom callback class loading"),
    ("real", "patch adds DOCTYPE, entity and secure-processing restrictions to the ZUGFeRD visualizer factory"),
    ("real", "patch adds DOCTYPE, entity and secure-processing restrictions to the XMLValidator factory"),
    ("real", "patch adds DOCTYPE, entity and secure-processing restrictions to the ZUGFeRDValidator factory"),
    ("not-real", "patch escapes HTML for the stored-XSS advisory; the flagged SHA-1 digest is unchanged"),
]


def main() -> None:
    sample = json.loads((HERE / "adjudication_sample.json").read_text(encoding="utf-8"))
    if len(sample) != len(VERDICTS):
        raise SystemExit(f"expected {len(VERDICTS)} rows, got {len(sample)}")

    rows = []
    for entry, (verdict, reason) in zip(sample, VERDICTS):
        rows.append(
            {
                "id": entry["id"],
                "tags": entry["tags"],
                "verdict": verdict,
                "reason": reason,
            }
        )

    groups = {}
    for tag in ("off-CWE", "method-only", "on-CWE-sample"):
        subset = [row for row in rows if tag in row["tags"]]
        counts = Counter(row["verdict"] for row in subset)
        groups[tag] = {
            "n": len(subset),
            "real": counts["real"],
            "partial": counts["partial"],
            "not-real": counts["not-real"],
            "real_rate": round(counts["real"] / len(subset), 4),
        }

    overall = Counter(row["verdict"] for row in rows)
    out = {
        "sample": {
            "rows": len(rows),
            "off-CWE": sum("off-CWE" in row["tags"] for row in rows),
            "method-only": sum("method-only" in row["tags"] for row in rows),
            "on-CWE-sample": sum("on-CWE-sample" in row["tags"] for row in rows),
        },
        "overall": {
            "real": overall["real"],
            "partial": overall["partial"],
            "not-real": overall["not-real"],
        },
        "groups": groups,
        "rows": rows,
    }

    (HERE / "adjudication.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps({"overall": out["overall"], "groups": groups}, indent=2))


if __name__ == "__main__":
    main()
