# Label adjudication packet

64 rows: 32 off-CWE, 41 method-only, 15 random on-CWE. Groups overlap.

## 1. GHSA-2jc4-r94c-rp7h:java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing.documentbuilderfactory-disallow-doctype-decl-missing:src/java/org/apache/ivy/util/XMLHelper.java:227

- tags: on-CWE-sample, hunk
- advisory: Apache Ivy External Entity Reference vulnerability
- repo: apache/ant-ivy  commit: 2be17bc18b0e1d4123007d579e43ba1a4b6fab3d
- entry CWE: ['CWE-611']  finding CWEs: ['CWE-611']
- rule: documentbuilderfactory-disallow-doctype-decl-missing
- finding: src/java/org/apache/ivy/util/XMLHelper.java:227 method getDocBuilder
- message: DOCTYPE declarations are enabled for this DocumentBuilderFactory. This is vulnerable to XML external entity attacks. Disable this by setting the feature "http://apache.org/xml/features/disallow-doctype-decl" to true. Alternatively, allow DOCTYPE declarations and only prohibit external entities declarations. This can be done by setting the features "http://xml.org/sax/features/external-general-entities" and "http://xml.org/sax/features/external-parameter-entities" to false.

```java
public abstract class XMLHelper {

    public static DocumentBuilder getDocBuilder(EntityResolver entityResolver) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setValidating(false);
            DocumentBuilder docBuilder = factory.newDocumentBuilder();
            if (entityResolver != null) {
                docBuilder.setEntityResolver(entityResolver);
            }
            return docBuilder;
        } catch (ParserConfigurationException e) {
            throw new RuntimeException(e);
        }
    }
```

```diff
@@ -19,6 +19,7 @@
 import java.io.InputStream;
+import java.io.StringReader;
 import java.net.URI;
@@ -28,13 +29,24 @@
 import javax.xml.parsers.SAXParserFactory;
+import javax.xml.transform.Source;
+import javax.xml.transform.Transformer;
+import javax.xml.transform.TransformerConfigurationException;
+import javax.xml.transform.TransformerFactory;
+import javax.xml.transform.sax.SAXTransformerFactory;
+import javax.xml.transform.sax.TransformerHandler;
 
 import org.w3c.dom.Document;
+import org.xml.sax.Attributes;
 import org.xml.sax.EntityResolver;
 import org.xml.sax.InputSource;
+import org.xml.sax.Locator;
 import org.xml.sax.SAXException;
 import org.xml.sax.SAXNotRecognizedException;
+import org.xml.sax.SAXNotSupportedException;
+import org.xml.sax.SAXParseException;
+import org.xml.sax.XMLReader;
 import org.xml.sax.ext.LexicalHandler;
@@ -50,49 +62,38 @@ public abstract class XMLHelper {
 
-    private static boolean canUseSchemaValidation = true;
+    private static final String XML_ACCESS_EXTERNAL_SCHEMA = "http://javax.xml.XMLConstants/property/accessExternalSchema";
+    private static final String XML_ACCESS_EXTERNAL_DTD = "http://javax.xml.XMLConstants/property/accessExternalDTD";
+    public static final String ALLOW_DOCTYPE_PROCESSING = "ivy.xml.allow-doctype-processing";
+    public static final String EXTERNAL_RESOURCES = "ivy.xml.external-resources";
 
-    private static Boolean canDisableExternalDtds = null;
-
-    private static SAXParser newSAXParser(URL schema, InputStream schemaStream,
-            boolean loadExternalDtds) throws ParserConfigurationException, SAXException {
-        SAXParserFactory parserFactory = SAXParserFactory.newInstance();
+    private static SAXParser newSAXParser(final URL schema, final InputStream schemaStream,
+        final boolean allowXmlDoctypeProcessing, final ExternalResources externalResources)
+        throws ParserConfigurationException, SAXException {
+        final SAXParserFactory parserFactory = SAXParserFactory.newInstance();
         parserFactory.setNamespaceAware(true);
-        parserFactory.setValidating(canUseSchemaValidation && (schema != null));
-        if (!loadExternalDtds && canDisableExternalDtds(parserFactory)) {
-            parserFactory.setFeature(XERCES_LOAD_EXTERNAL_DTD, false);
-        }
-        SAXParser parser = parserFactory.newSAXParser();
+        parserFactory.setValidating(schema != null);
+        configureSafeFeatures(parserFactory, allowXmlDoctypeProcessing, externalResources);
 
-        if (canUseSchemaValidation && schema != null) {
+        SAXParser parser = parserFactory.newSAXParser();
+        if (schema != null) {
             try {
                         + "XML validation will not be done", ex);
-                canUseSchemaValidation = false;
                 parserFactory.setValidating(false);
         }
-
-        parser.getXMLReader().setFeature(XML_NAMESPACE_PREFIXES, true);
+        final XMLReader reader = parser.getXMLReader();
+        reader.setFeature(XML_NAMESPACE_PREFIXES, true);
+        reader.setProperty(XML_ACCESS_EXTERNAL_SCHEMA, externalResources.getAllowedProtocols());
+        reader.setProperty(XML_ACCESS_EXTERNAL_DTD, externalResources.getAllowedProtocols());
         return parser;
 
-    private static boolean canDisableExternalDtds(SAXParserFactory parserFactory) {
-        if (canDisableExternalDtds == null) {
-            try {
-                parserFactory.getFeature(XERCES_LOAD_EXTERNAL_DTD);
... (truncated)
```

## 2. GHSA-3gm7-v7vw-866c:java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing.documentbuilderfactory-disallow-doctype-decl-missing:solr/contrib/dataimporthandler/src/java/org/apache/solr/handler/dataimport/DataImporter.java:205

- tags: off-CWE, hunk
- advisory: XML External Entity (XXE) Injection in Apache Solr
- repo: apache/lucene-solr  commit: 02c693f3713add1b4891cbaa87127de3a55c10f7
- entry CWE: ['CWE-94']  finding CWEs: ['CWE-611']
- rule: documentbuilderfactory-disallow-doctype-decl-missing
- finding: solr/contrib/dataimporthandler/src/java/org/apache/solr/handler/dataimport/DataImporter.java:205 method loadDataConfig
- message: DOCTYPE declarations are enabled for this DocumentBuilderFactory. This is vulnerable to XML external entity attacks. Disable this by setting the feature "http://apache.org/xml/features/disallow-doctype-decl" to true. Alternatively, allow DOCTYPE declarations and only prohibit external entities declarations. This can be done by setting the features "http://xml.org/sax/features/external-general-entities" and "http://xml.org/sax/features/external-parameter-entities" to false.

```java
public class DataImporter {

  public DIHConfiguration loadDataConfig(InputSource configFile) {

    DIHConfiguration dihcfg = null;
    try {
      DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
      
      // only enable xinclude, if a a SolrCore and SystemId is present (makes no sense otherwise)
      if (core != null && configFile.getSystemId() != null) {
        try {
          dbf.setXIncludeAware(true);
          dbf.setNamespaceAware(true);
        } catch( UnsupportedOperationException e ) {
          LOG.warn( "XML parser doesn't support XInclude option" );
        }
      }
      
      DocumentBuilder builder = dbf.newDocumentBuilder();
      if (core != null)
        builder.setEntityResolver(new SystemIdResolver(core.getResourceLoader()));
      builder.setErrorHandler(XMLLOG);
      Document document;
      try {
        document = builder.parse(configFile);
      } finally {
        // some XML parsers are broken and don't close the byte stream (but they should according to spec)
        IOUtils.closeQuietly(configFile.getByteStream());
      }

      dihcfg = readFromXml(document);
      LOG.info("Data Configuration loaded successfully");
    } catch (Exception e) {
      throw new DataImportHandlerException(SEVERE,
              "Data Config problem: " + e.getMessage(), e);
    }
    for (Entity e : dihcfg.getEntities()) {
      if (e.getAllAttributes().containsKey(SqlEntityProcessor.DELTA_QUERY)) {
        isDeltaImportSupported = true;
        break;
      }
    }
    return dihcfg;
  }
```

```diff
@@ -16,6 +16,7 @@
 
+import org.apache.solr.common.EmptyEntityResolver;
 import org.apache.solr.common.SolrException;
@@ -178,11 +179,11 @@ public IndexSchema getSchema() {
    */
-  public void loadAndInit(String configStr) {
+  void loadAndInit(String configStr) {
     config = loadDataConfig(new InputSource(new StringReader(configStr)));
 
-  public void loadAndInit(InputSource configFile) {
+  void loadAndInit(InputSource configFile) {
     config = loadDataConfig(configFile);
@@ -191,8 +192,10 @@ public DIHConfiguration loadDataConfig(InputSource configFile) {
       DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
+      dbf.setValidating(false);
       
-      // only enable xinclude, if a a SolrCore and SystemId is present (makes no sense otherwise)
+      // only enable xinclude, if XML is coming from safe source (local file)
+      // and a a SolrCore and SystemId is present (makes no sense otherwise):
       if (core != null && configFile.getSystemId() != null) {
@@ -203,8 +206,14 @@ public DIHConfiguration loadDataConfig(InputSource configFile) {
       DocumentBuilder builder = dbf.newDocumentBuilder();
-      if (core != null)
+      // only enable xinclude / external entities, if XML is coming from
+      // safe source (local file) and a a SolrCore and SystemId is present:
+      if (core != null && configFile.getSystemId() != null) {
         builder.setEntityResolver(new SystemIdResolver(core.getResourceLoader()));
+      } else {
+        // Don't allow external entities without having a system ID:
+        builder.setEntityResolver(EmptyEntityResolver.SAX_INSTANCE);
+      }
       builder.setErrorHandler(XMLLOG);
```

## 3. GHSA-3mcp-9wr4-cjqf:java.lang.security.audit.el-injection.el-injection:dropwizard-validation/src/main/java/io/dropwizard/validation/selfvalidating/ViolationCollector.java:24

- tags: off-CWE, hunk
- advisory: Remote Code Execution (RCE) vulnerability in dropwizard-validation
- repo: dropwizard/dropwizard  commit: 28479f743a9d0aab6d0e963fc07f3dd98e8c8236
- entry CWE: ['CWE-74']  finding CWEs: ['CWE-94']
- rule: el-injection
- finding: dropwizard-validation/src/main/java/io/dropwizard/validation/selfvalidating/ViolationCollector.java:24 method addViolation
- message: An expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.

```java
public class ViolationCollector {

    public void addViolation(String msg) {
        violationOccurred = true;
        context.buildConstraintViolationWithTemplate(msg)
            .addConstraintViolation();
    }
```

```diff
@@ -1,12 +1,16 @@
 
+import javax.annotation.Nullable;
 import javax.validation.ConstraintValidatorContext;
+import java.util.regex.Matcher;
+import java.util.regex.Pattern;
 
 public class ViolationCollector {
+    private static final Pattern ESCAPE_PATTERN = Pattern.compile("\\$\\{");
 
@@ -17,14 +21,80 @@ public ViolationCollector(ConstraintValidatorContext context) {
     /**
-     * Adds a new violation to this collector. This also sets violationOccurred to true.
+     * Adds a new violation to this collector. This also sets {@code violationOccurred} to {@code true}.
      *
-     * @param msg the message of the violation
+     * @param message the message of the violation (any EL expression will be escaped and not parsed)
      */
-    public void addViolation(String msg) {
+    public void addViolation(String message) {
         violationOccurred = true;
-        context.buildConstraintViolationWithTemplate(msg)
-            .addConstraintViolation();
+        String messageTemplate = escapeEl(message);
+        context.buildConstraintViolationWithTemplate(messageTemplate)
+                .addConstraintViolation();
+    }
+
+    /**
+     * Adds a new violation to this collector. This also sets {@code violationOccurred} to {@code true}.
+     *
+     * @param propertyName the name of the property
+     * @param message      the message of the violation (any EL expression will be escaped and not parsed)
+     * @since 1.3.19
+     */
+    public void addViolation(String propertyName, String message) {
+        violationOccurred = true;
+        String messageTemplate = escapeEl(message);
+        context.buildConstraintViolationWithTemplate(messageTemplate)
+                .addPropertyNode(propertyName)
+                .addConstraintViolation();
+    }
+
+    /**
+     * Adds a new violation to this collector. This also sets {@code violationOccurred} to {@code true}.
+     *
+     * @param propertyName the name of the property with the violation
+     * @param index        the index of the element with the violation
+     * @param message      the message of the violation (any EL expression will be escaped and not parsed)
+     * @since 1.3.19
+     */
+    public void addViolation(String propertyName, Integer index, String message) {
+        violationOccurred = true;
+        String messageTemplate = escapeEl(message);
+        context.buildConstraintViolationWithTemplate(messageTemplate)
+                .addPropertyNode(propertyName)
+                .addBeanNode().inIterable().atIndex(index)
+                .addConstraintViolation();
+    }
+
+    /**
+     * Adds a new violation to this collector. This also sets {@code violationOccurred} to {@code true}.
+     *
+     * @param propertyName the name of the property with the violation
+     * @param key          the key of the element with the violation
+     * @param message      the message of the violation (any EL expression will be escaped and not parsed)
+     * @since 1.3.19
+     */
+    public void addViolation(String propertyName, String key, String message) {
+        violationOccurred = true;
... (truncated)
```

## 4. GHSA-3ppr-72x5-x67q:java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing.documentbuilderfactory-disallow-doctype-decl-missing:src/main/java/hudson/plugins/mstest/MSTestReportConverter.java:116

- tags: method-only
- advisory: XML external entity vulnerability on agents in Jenkins MSTest Plugin 
- repo: jenkinsci/mstest-plugin  commit: f9b9b0cbdf7559fdd8fc4004e5a242f5801daa67
- entry CWE: ['CWE-611']  finding CWEs: ['CWE-611']
- rule: documentbuilderfactory-disallow-doctype-decl-missing
- finding: src/main/java/hudson/plugins/mstest/MSTestReportConverter.java:116 method containsData
- message: DOCTYPE declarations are enabled for this DocumentBuilderFactory. This is vulnerable to XML external entity attacks. Disable this by setting the feature "http://apache.org/xml/features/disallow-doctype-decl" to true. Alternatively, allow DOCTYPE declarations and only prohibit external entities declarations. This can be done by setting the features "http://xml.org/sax/features/external-general-entities" and "http://xml.org/sax/features/external-parameter-entities" to false.

```java
class MSTestReportConverter implements Serializable {

    private boolean containsData(File c) throws IOException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        try {
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(c);
            XPathFactory xPathfactory = XPathFactory.newInstance();
            XPath xpath = xPathfactory.newXPath();
            XPathExpression expr = xpath.compile("count(/CoverageDSPriv/*)");
            Double childCount = (Double) expr.evaluate(doc, XPathConstants.NUMBER);
            return childCount > 0;
        } catch (ParserConfigurationException | SAXException | XPathExpressionException ex) {
            MsTestLogger.getLogger()
                .error("Caught a XML parsing related exception: %s", ex.getMessage());
        }
        return false;
    }
```

```diff
@@ -8,6 +8,7 @@
 import java.util.List;
+import javax.xml.XMLConstants;
 import javax.xml.parsers.DocumentBuilder;
@@ -113,6 +114,14 @@ private void convertToEmma(File f, File c)
         try {
+            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
+            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
+            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
+            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
+
+            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
+            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
+
             DocumentBuilder builder = factory.newDocumentBuilder();
@@ -148,6 +157,12 @@ private DocumentBuilder getDocumentBuilder()
         DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
+        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
+        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
+        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
+        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
+        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
+        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
         return factory.newDocumentBuilder();
```

## 5. GHSA-3ppr-72x5-x67q:java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing.documentbuilderfactory-disallow-doctype-decl-missing:src/main/java/hudson/plugins/mstest/MSTestReportConverter.java:151

- tags: method-only
- advisory: XML external entity vulnerability on agents in Jenkins MSTest Plugin 
- repo: jenkinsci/mstest-plugin  commit: f9b9b0cbdf7559fdd8fc4004e5a242f5801daa67
- entry CWE: ['CWE-611']  finding CWEs: ['CWE-611']
- rule: documentbuilderfactory-disallow-doctype-decl-missing
- finding: src/main/java/hudson/plugins/mstest/MSTestReportConverter.java:151 method getDocumentBuilder
- message: DOCTYPE declarations are enabled for this DocumentBuilderFactory. This is vulnerable to XML external entity attacks. Disable this by setting the feature "http://apache.org/xml/features/disallow-doctype-decl" to true. Alternatively, allow DOCTYPE declarations and only prohibit external entities declarations. This can be done by setting the features "http://xml.org/sax/features/external-general-entities" and "http://xml.org/sax/features/external-parameter-entities" to false.

```java
class MSTestReportConverter implements Serializable {

    private DocumentBuilder getDocumentBuilder()
        throws TransformerFactoryConfigurationError,
        ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        return factory.newDocumentBuilder();
    }
```

```diff
@@ -8,6 +8,7 @@
 import java.util.List;
+import javax.xml.XMLConstants;
 import javax.xml.parsers.DocumentBuilder;
@@ -113,6 +114,14 @@ private void convertToEmma(File f, File c)
         try {
+            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
+            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
+            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
+            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
+
+            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
+            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
+
             DocumentBuilder builder = factory.newDocumentBuilder();
@@ -148,6 +157,12 @@ private DocumentBuilder getDocumentBuilder()
         DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
+        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
+        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
+        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
+        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
+        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
+        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
         return factory.newDocumentBuilder();
```

## 6. GHSA-3ppr-72x5-x67q:java.lang.security.audit.xxe.transformerfactory-dtds-not-disabled.transformerfactory-dtds-not-disabled:src/main/java/hudson/plugins/mstest/XslTransformer.java:25

- tags: method-only
- advisory: XML external entity vulnerability on agents in Jenkins MSTest Plugin 
- repo: jenkinsci/mstest-plugin  commit: f9b9b0cbdf7559fdd8fc4004e5a242f5801daa67
- entry CWE: ['CWE-611']  finding CWEs: ['CWE-611']
- rule: transformerfactory-dtds-not-disabled
- finding: src/main/java/hudson/plugins/mstest/XslTransformer.java:25 method 
- message: DOCTYPE declarations are enabled for this TransformerFactory. This is vulnerable to XML external entity attacks. Disable this by setting the attributes "accessExternalDTD" and "accessExternalStylesheet" to "".

```java
class XslTransformer {

    private final transient Transformer xslTransformer;

    XslTransformer()
        throws TransformerConfigurationException {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        xslTransformer = transformerFactory.newTransformer();
    }

    private XslTransformer(String xslTransform)
        throws TransformerConfigurationException {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        xslTransformer = transformerFactory
            .newTransformer(new StreamSource(this.getClass().getResourceAsStream(xslTransform)));
    }

    static XslTransformer FromResource(String resourceName)
        throws TransformerConfigurationException {
        return new XslTransformer(resourceName);
```

```diff
@@ -4,6 +4,7 @@
 import java.io.InputStream;
+import javax.xml.XMLConstants;
 import javax.xml.transform.Transformer;
@@ -22,12 +23,16 @@ class XslTransformer {
         TransformerFactory transformerFactory = TransformerFactory.newInstance();
+        transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
+        transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
         xslTransformer = transformerFactory.newTransformer();
         TransformerFactory transformerFactory = TransformerFactory.newInstance();
+        transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
+        transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
         xslTransformer = transformerFactory
```

## 7. GHSA-3ppr-72x5-x67q:java.lang.security.audit.xxe.transformerfactory-dtds-not-disabled.transformerfactory-dtds-not-disabled:src/main/java/hudson/plugins/mstest/XslTransformer.java:31

- tags: method-only
- advisory: XML external entity vulnerability on agents in Jenkins MSTest Plugin 
- repo: jenkinsci/mstest-plugin  commit: f9b9b0cbdf7559fdd8fc4004e5a242f5801daa67
- entry CWE: ['CWE-611']  finding CWEs: ['CWE-611']
- rule: transformerfactory-dtds-not-disabled
- finding: src/main/java/hudson/plugins/mstest/XslTransformer.java:31 method 
- message: DOCTYPE declarations are enabled for this TransformerFactory. This is vulnerable to XML external entity attacks. Disable this by setting the attributes "accessExternalDTD" and "accessExternalStylesheet" to "".

```java
package hudson.plugins.mstest;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;


    private final transient Transformer xslTransformer;

    XslTransformer()
        throws TransformerConfigurationException {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        xslTransformer = transformerFactory.newTransformer();
    }

    private XslTransformer(String xslTransform)
        throws TransformerConfigurationException {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        xslTransformer = transformerFactory
            .newTransformer(new StreamSource(this.getClass().getResourceAsStream(xslTransform)));
    }

    static XslTransformer FromResource(String resourceName)
        throws TransformerConfigurationException {
        return new XslTransformer(resourceName);
    }

    void transform(InputStream inputStream, File outputFile)
        throws TransformerException, IOException {
        try (FileOutputStream fileOutputStream = new FileOutputStream(outputFile)) {
            xslTransformer
```

```diff
@@ -4,6 +4,7 @@
 import java.io.InputStream;
+import javax.xml.XMLConstants;
 import javax.xml.transform.Transformer;
@@ -22,12 +23,16 @@ class XslTransformer {
         TransformerFactory transformerFactory = TransformerFactory.newInstance();
+        transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
+        transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
         xslTransformer = transformerFactory.newTransformer();
         TransformerFactory transformerFactory = TransformerFactory.newInstance();
+        transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
+        transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
         xslTransformer = transformerFactory
```

## 8. GHSA-3vrc-rrpw-r5pw:java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing.documentbuilderfactory-disallow-doctype-decl-missing:src/main/java/com/jamesmurty/utils/BaseXMLBuilder.java:134

- tags: method-only, on-CWE-sample
- advisory: java-xmlbuilder vulnerable to XML External Entity Reference
- repo: jmurty/java-xmlbuilder  commit: e6fddca201790abab4f2c274341c0bb8835c3e73
- entry CWE: ['CWE-611']  finding CWEs: ['CWE-611']
- rule: documentbuilderfactory-disallow-doctype-decl-missing
- finding: src/main/java/com/jamesmurty/utils/BaseXMLBuilder.java:134 method createDocumentImpl
- message: DOCTYPE declarations are enabled for this DocumentBuilderFactory. This is vulnerable to XML external entity attacks. Disable this by setting the feature "http://apache.org/xml/features/disallow-doctype-decl" to true. Alternatively, allow DOCTYPE declarations and only prohibit external entities declarations. This can be done by setting the features "http://xml.org/sax/features/external-general-entities" and "http://xml.org/sax/features/external-parameter-entities" to false.

```java
public abstract class BaseXMLBuilder {

    protected static Document createDocumentImpl(String name, String namespaceURI)
        throws ParserConfigurationException, FactoryConfigurationError
    {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(isNamespaceAware);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.newDocument();
        Element rootElement = null;
        if (namespaceURI != null && namespaceURI.length() > 0) {
            rootElement = document.createElementNS(namespaceURI, name);
        } else {
            rootElement = document.createElement(name);
        }
        document.appendChild(rootElement);
        return document;
    }
```

```diff
@@ -76,6 +76,13 @@ public abstract class BaseXMLBuilder {
 
+    /**
+     * If true, the builder will raise an {@link XMLBuilderRuntimeException}
+     * if external general and parameter entities cannot be explicitly enabled
+     * or disabled.
+     */
+    public static boolean failIfExternalEntityParsingCannotBeConfigured = true;
+
     /**
@@ -112,6 +119,78 @@ protected BaseXMLBuilder(Node myNode, Node parentNode) {
 
+    /**
+     * Explicitly enable or disable the 'external-general-entities' and
+     * 'external-parameter-entities' features of the underlying
+     * DocumentBuilderFactory.
+     *
+     * TODO This is a naive approach that simply tries to apply all known
+     * feature name/URL values in turn until one succeeds, or none do.
+     *
+     * @param factory
+     * factory which will have external general and parameter entities enabled
+     * or disabled.
+     * @param enableExternalEntities
+     * if true external entities will be explicitly enabled, otherwise they
+     * will be explicitly disabled.
+     */
+    protected static void enableOrDisableExternalEntityParsing(
+        DocumentBuilderFactory factory, boolean enableExternalEntities)
+    {
+        // Feature list drawn from:
+        // https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing
+
+        /* Enable or disable external general entities */
+        String[] externalGeneralEntitiesFeatures = {
+            // General
+            "http://xml.org/sax/features/external-general-entities",
+            // Xerces 1
+            "http://xerces.apache.org/xerces-j/features.html#external-general-entities",
+            // Xerces 2
+            "http://xerces.apache.org/xerces2-j/features.html#external-general-entities",
+        };
+        boolean success = false;
+        for (String feature: externalGeneralEntitiesFeatures) {
+            try {
+                factory.setFeature(feature, enableExternalEntities);
+                success = true;
+                break;
+            } catch (ParserConfigurationException e) {
+            }
+        }
+        if (!success && failIfExternalEntityParsingCannotBeConfigured) {
+            throw new XMLBuilderRuntimeException(
+                new ParserConfigurationException(
+                    "Failed to set 'external-general-entities' feature to "
+                    + enableExternalEntities));
+        }
+
+        /* Enable or disable external parameter entities */
+        String[] externalParameterEntitiesFeatures = {
+            // General
+            "http://xml.org/sax/features/external-parameter-entities",
+            // Xerces 1
+            "http://xerces.apache.org/xerces-j/features.html#external-parameter-entities",
+            // Xerces 2
+            "http://xerces.apache.org/xerces2-j/features.html#external-parameter-entities",
+        };
+        success = false;
+        for (String feature: externalParameterEntitiesFeatures) {
+            try {
... (truncated)
```

## 9. GHSA-3vrc-rrpw-r5pw:java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing.documentbuilderfactory-disallow-doctype-decl-missing:src/main/java/com/jamesmurty/utils/BaseXMLBuilder.java:165

- tags: method-only
- advisory: java-xmlbuilder vulnerable to XML External Entity Reference
- repo: jmurty/java-xmlbuilder  commit: e6fddca201790abab4f2c274341c0bb8835c3e73
- entry CWE: ['CWE-611']  finding CWEs: ['CWE-611']
- rule: documentbuilderfactory-disallow-doctype-decl-missing
- finding: src/main/java/com/jamesmurty/utils/BaseXMLBuilder.java:165 method parseDocumentImpl
- message: DOCTYPE declarations are enabled for this DocumentBuilderFactory. This is vulnerable to XML external entity attacks. Disable this by setting the feature "http://apache.org/xml/features/disallow-doctype-decl" to true. Alternatively, allow DOCTYPE declarations and only prohibit external entities declarations. This can be done by setting the features "http://xml.org/sax/features/external-general-entities" and "http://xml.org/sax/features/external-parameter-entities" to false.

```java
public abstract class BaseXMLBuilder {

    protected static Document parseDocumentImpl(InputSource inputSource)
        throws ParserConfigurationException, SAXException, IOException
    {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(isNamespaceAware);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(inputSource);
        return document;
    }
```

```diff
@@ -76,6 +76,13 @@ public abstract class BaseXMLBuilder {
 
+    /**
+     * If true, the builder will raise an {@link XMLBuilderRuntimeException}
+     * if external general and parameter entities cannot be explicitly enabled
+     * or disabled.
+     */
+    public static boolean failIfExternalEntityParsingCannotBeConfigured = true;
+
     /**
@@ -112,6 +119,78 @@ protected BaseXMLBuilder(Node myNode, Node parentNode) {
 
+    /**
+     * Explicitly enable or disable the 'external-general-entities' and
+     * 'external-parameter-entities' features of the underlying
+     * DocumentBuilderFactory.
+     *
+     * TODO This is a naive approach that simply tries to apply all known
+     * feature name/URL values in turn until one succeeds, or none do.
+     *
+     * @param factory
+     * factory which will have external general and parameter entities enabled
+     * or disabled.
+     * @param enableExternalEntities
+     * if true external entities will be explicitly enabled, otherwise they
+     * will be explicitly disabled.
+     */
+    protected static void enableOrDisableExternalEntityParsing(
+        DocumentBuilderFactory factory, boolean enableExternalEntities)
+    {
+        // Feature list drawn from:
+        // https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing
+
+        /* Enable or disable external general entities */
+        String[] externalGeneralEntitiesFeatures = {
+            // General
+            "http://xml.org/sax/features/external-general-entities",
+            // Xerces 1
+            "http://xerces.apache.org/xerces-j/features.html#external-general-entities",
+            // Xerces 2
+            "http://xerces.apache.org/xerces2-j/features.html#external-general-entities",
+        };
+        boolean success = false;
+        for (String feature: externalGeneralEntitiesFeatures) {
+            try {
+                factory.setFeature(feature, enableExternalEntities);
+                success = true;
+                break;
+            } catch (ParserConfigurationException e) {
+            }
+        }
+        if (!success && failIfExternalEntityParsingCannotBeConfigured) {
+            throw new XMLBuilderRuntimeException(
+                new ParserConfigurationException(
+                    "Failed to set 'external-general-entities' feature to "
+                    + enableExternalEntities));
+        }
+
+        /* Enable or disable external parameter entities */
+        String[] externalParameterEntitiesFeatures = {
+            // General
+            "http://xml.org/sax/features/external-parameter-entities",
+            // Xerces 1
+            "http://xerces.apache.org/xerces-j/features.html#external-parameter-entities",
+            // Xerces 2
+            "http://xerces.apache.org/xerces2-j/features.html#external-parameter-entities",
+        };
+        success = false;
+        for (String feature: externalParameterEntitiesFeatures) {
+            try {
... (truncated)
```

## 10. GHSA-3xrr-7m6p-p7xh:java.lang.security.audit.xxe.transformerfactory-dtds-not-disabled.transformerfactory-dtds-not-disabled:src/main/java/com/gargoylesoftware/htmlunit/javascript/host/xml/XSLTProcessor.java:144

- tags: off-CWE, method-only
- advisory: HtmlUnit Code Injection vulnerability
- repo: HtmlUnit/htmlunit  commit: 641325bbc84702dc9800ec7037aec061ce21956b
- entry CWE: ['CWE-74', 'CWE-94']  finding CWEs: ['CWE-611']
- rule: transformerfactory-dtds-not-disabled
- finding: src/main/java/com/gargoylesoftware/htmlunit/javascript/host/xml/XSLTProcessor.java:144 method transform
- message: DOCTYPE declarations are enabled for this TransformerFactory. This is vulnerable to XML external entity attacks. Disable this by setting the attributes "accessExternalDTD" and "accessExternalStylesheet" to "".

```java
public class XSLTProcessor extends HtmlUnitScriptable {

    private Object transform(final Node source) {
        try {
            final DomNode sourceDomNode = source.getDomNodeOrDie();
            Source xmlSource = new DOMSource(sourceDomNode);

            final DomNode xsltDomNode = style_.getDomNodeOrDie();
            final Source xsltSource = new DOMSource(xsltDomNode);

            final TransformerFactory transformerFactory = TransformerFactory.newInstance();

            final SgmlPage page = sourceDomNode.getPage();
            if (page != null && page.getWebClient().getBrowserVersion()
                                            .hasFeature(JS_XSLT_TRANSFORM_INDENT)) {
                final DomNode outputNode = findOutputNode(xsltDomNode);
                if (outputNode != null) {
                    final org.w3c.dom.Node indentNode = outputNode.getAttributes().getNamedItem("indent");
                    if (indentNode != null && "yes".equalsIgnoreCase(indentNode.getNodeValue())) {
                        try {
                            transformerFactory.setAttribute("indent-number", new Integer(2));
                        }
                        catch (final IllegalArgumentException e) {
                            // ignore
                        }
                        final Transformer transformer = transformerFactory.newTransformer(xsltSource);
                        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
                        try {
                            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
                        }
                        catch (final IllegalArgumentException e) {
                            // ignore
                        }

                        for (final Map.Entry<String, Object> entry : parameters_.entrySet()) {
                            transformer.setParameter(entry.getKey(), entry.getValue());
                        }

                        // hack to preserve indention
                        // the transformer only accepts the OutputKeys.INDENT setting if
                        // the StreamResult is used
                        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                            transformer.transform(xmlSource, new StreamResult(out));
                            final WebResponseData data =
                                    new WebResponseData(out.toByteArray(), 200, null, Collections.emptyList());
                            final WebResponse response = new WebResponse(data, null, 0);
                            return XmlUtils.buildDocument(response);
                        }
                    }
                }
            }

            final Transformer transformer = transformerFactory.newTransformer(xsltSource);
            for (final Map.Entry<String, Object> entry : parameters_.entrySet()) {
                transformer.setParameter(entry.getKey(), entry.getValue());
            }

            final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            final org.w3c.dom.Document containerDocument = factory.newDocumentBuilder().newDocument();
            final org.w3c.dom.Element containerElement = containerDocument.createElement("container");
            containerDocument.appendChild(containerElement);

            final DOMResult result = new DOMResult(containerElement);
            transformer.transform(xmlSource, result);

            final org.w3c.dom.Node transformedNode = result.getNode();
            final org.w3c.dom.Node transformedFirstChild = transformedNode.getFirstChild();
            if (transformedFirstChild != null && transformedFirstChild.getNodeType() == Node.ELEMENT_NODE) {
                return transformedNode;
            }

            // output is not DOM (text)
            xmlSource = new DOMSource(source.getDomNodeOrDie());
            final StringWriter writer = new StringWriter();
            final Result streamResult = new StreamResult(writer);
            transformer.transform(xmlSource, streamResult);
            return writer.toString();
        }
        catch (final Exception e) {
            throw Context.reportRuntimeError("Exception: " + e);
        }
    }
```

```diff
@@ -26,6 +26,7 @@
 
+import javax.xml.XMLConstants;
 import javax.xml.parsers.DocumentBuilderFactory;
@@ -128,6 +129,11 @@ private Object transform(final Node source) {
 
+            // By default, the JDK turns on FSP for DOM and SAX parsers and XML schema validators,
+            // which sets a number of processing limits on the processors. Conversely, by default,
+            // the JDK turns off FSP for transformers and XPath, which enables extension functions for XSLT and XPath.
+            transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
+
             final SgmlPage page = sourceDomNode.getPage();
```

## 11. GHSA-3xrr-7m6p-p7xh:java.lang.security.audit.xxe.transformerfactory-dtds-not-disabled.transformerfactory-dtds-not-disabled:src/main/java/com/gargoylesoftware/htmlunit/javascript/host/xml/XSLTProcessor.java:171

- tags: off-CWE, method-only
- advisory: HtmlUnit Code Injection vulnerability
- repo: HtmlUnit/htmlunit  commit: 641325bbc84702dc9800ec7037aec061ce21956b
- entry CWE: ['CWE-74', 'CWE-94']  finding CWEs: ['CWE-611']
- rule: transformerfactory-dtds-not-disabled
- finding: src/main/java/com/gargoylesoftware/htmlunit/javascript/host/xml/XSLTProcessor.java:171 method transform
- message: DOCTYPE declarations are enabled for this TransformerFactory. This is vulnerable to XML external entity attacks. Disable this by setting the attributes "accessExternalDTD" and "accessExternalStylesheet" to "".

```java
public class XSLTProcessor extends HtmlUnitScriptable {

    private Object transform(final Node source) {
        try {
            final DomNode sourceDomNode = source.getDomNodeOrDie();
            Source xmlSource = new DOMSource(sourceDomNode);

            final DomNode xsltDomNode = style_.getDomNodeOrDie();
            final Source xsltSource = new DOMSource(xsltDomNode);

            final TransformerFactory transformerFactory = TransformerFactory.newInstance();

            final SgmlPage page = sourceDomNode.getPage();
            if (page != null && page.getWebClient().getBrowserVersion()
                                            .hasFeature(JS_XSLT_TRANSFORM_INDENT)) {
                final DomNode outputNode = findOutputNode(xsltDomNode);
                if (outputNode != null) {
                    final org.w3c.dom.Node indentNode = outputNode.getAttributes().getNamedItem("indent");
                    if (indentNode != null && "yes".equalsIgnoreCase(indentNode.getNodeValue())) {
                        try {
                            transformerFactory.setAttribute("indent-number", new Integer(2));
                        }
                        catch (final IllegalArgumentException e) {
                            // ignore
                        }
                        final Transformer transformer = transformerFactory.newTransformer(xsltSource);
                        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
                        try {
                            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
                        }
                        catch (final IllegalArgumentException e) {
                            // ignore
                        }

                        for (final Map.Entry<String, Object> entry : parameters_.entrySet()) {
                            transformer.setParameter(entry.getKey(), entry.getValue());
                        }

                        // hack to preserve indention
                        // the transformer only accepts the OutputKeys.INDENT setting if
                        // the StreamResult is used
                        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                            transformer.transform(xmlSource, new StreamResult(out));
                            final WebResponseData data =
                                    new WebResponseData(out.toByteArray(), 200, null, Collections.emptyList());
                            final WebResponse response = new WebResponse(data, null, 0);
                            return XmlUtils.buildDocument(response);
                        }
                    }
                }
            }

            final Transformer transformer = transformerFactory.newTransformer(xsltSource);
            for (final Map.Entry<String, Object> entry : parameters_.entrySet()) {
                transformer.setParameter(entry.getKey(), entry.getValue());
            }

            final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            final org.w3c.dom.Document containerDocument = factory.newDocumentBuilder().newDocument();
            final org.w3c.dom.Element containerElement = containerDocument.createElement("container");
            containerDocument.appendChild(containerElement);

            final DOMResult result = new DOMResult(containerElement);
            transformer.transform(xmlSource, result);

            final org.w3c.dom.Node transformedNode = result.getNode();
            final org.w3c.dom.Node transformedFirstChild = transformedNode.getFirstChild();
            if (transformedFirstChild != null && transformedFirstChild.getNodeType() == Node.ELEMENT_NODE) {
                return transformedNode;
            }

            // output is not DOM (text)
            xmlSource = new DOMSource(source.getDomNodeOrDie());
            final StringWriter writer = new StringWriter();
            final Result streamResult = new StreamResult(writer);
            transformer.transform(xmlSource, streamResult);
            return writer.toString();
        }
        catch (final Exception e) {
            throw Context.reportRuntimeError("Exception: " + e);
        }
    }
```

```diff
@@ -26,6 +26,7 @@
 
+import javax.xml.XMLConstants;
 import javax.xml.parsers.DocumentBuilderFactory;
@@ -128,6 +129,11 @@ private Object transform(final Node source) {
 
+            // By default, the JDK turns on FSP for DOM and SAX parsers and XML schema validators,
+            // which sets a number of processing limits on the processors. Conversely, by default,
+            // the JDK turns off FSP for transformers and XPath, which enables extension functions for XSLT and XPath.
+            transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
+
             final SgmlPage page = sourceDomNode.getPage();
```

## 12. GHSA-3xrr-7m6p-p7xh:java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing.documentbuilderfactory-disallow-doctype-decl-missing:src/main/java/com/gargoylesoftware/htmlunit/javascript/host/xml/XSLTProcessor.java:177

- tags: off-CWE, method-only
- advisory: HtmlUnit Code Injection vulnerability
- repo: HtmlUnit/htmlunit  commit: 641325bbc84702dc9800ec7037aec061ce21956b
- entry CWE: ['CWE-74', 'CWE-94']  finding CWEs: ['CWE-611']
- rule: documentbuilderfactory-disallow-doctype-decl-missing
- finding: src/main/java/com/gargoylesoftware/htmlunit/javascript/host/xml/XSLTProcessor.java:177 method transform
- message: DOCTYPE declarations are enabled for this DocumentBuilderFactory. This is vulnerable to XML external entity attacks. Disable this by setting the feature "http://apache.org/xml/features/disallow-doctype-decl" to true. Alternatively, allow DOCTYPE declarations and only prohibit external entities declarations. This can be done by setting the features "http://xml.org/sax/features/external-general-entities" and "http://xml.org/sax/features/external-parameter-entities" to false.

```java
public class XSLTProcessor extends HtmlUnitScriptable {

    private Object transform(final Node source) {
        try {
            final DomNode sourceDomNode = source.getDomNodeOrDie();
            Source xmlSource = new DOMSource(sourceDomNode);

            final DomNode xsltDomNode = style_.getDomNodeOrDie();
            final Source xsltSource = new DOMSource(xsltDomNode);

            final TransformerFactory transformerFactory = TransformerFactory.newInstance();

            final SgmlPage page = sourceDomNode.getPage();
            if (page != null && page.getWebClient().getBrowserVersion()
                                            .hasFeature(JS_XSLT_TRANSFORM_INDENT)) {
                final DomNode outputNode = findOutputNode(xsltDomNode);
                if (outputNode != null) {
                    final org.w3c.dom.Node indentNode = outputNode.getAttributes().getNamedItem("indent");
                    if (indentNode != null && "yes".equalsIgnoreCase(indentNode.getNodeValue())) {
                        try {
                            transformerFactory.setAttribute("indent-number", new Integer(2));
                        }
                        catch (final IllegalArgumentException e) {
                            // ignore
                        }
                        final Transformer transformer = transformerFactory.newTransformer(xsltSource);
                        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
                        try {
                            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
                        }
                        catch (final IllegalArgumentException e) {
                            // ignore
                        }

                        for (final Map.Entry<String, Object> entry : parameters_.entrySet()) {
                            transformer.setParameter(entry.getKey(), entry.getValue());
                        }

                        // hack to preserve indention
                        // the transformer only accepts the OutputKeys.INDENT setting if
                        // the StreamResult is used
                        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                            transformer.transform(xmlSource, new StreamResult(out));
                            final WebResponseData data =
                                    new WebResponseData(out.toByteArray(), 200, null, Collections.emptyList());
                            final WebResponse response = new WebResponse(data, null, 0);
                            return XmlUtils.buildDocument(response);
                        }
                    }
                }
            }

            final Transformer transformer = transformerFactory.newTransformer(xsltSource);
            for (final Map.Entry<String, Object> entry : parameters_.entrySet()) {
                transformer.setParameter(entry.getKey(), entry.getValue());
            }

            final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            final org.w3c.dom.Document containerDocument = factory.newDocumentBuilder().newDocument();
            final org.w3c.dom.Element containerElement = containerDocument.createElement("container");
            containerDocument.appendChild(containerElement);

            final DOMResult result = new DOMResult(containerElement);
            transformer.transform(xmlSource, result);

            final org.w3c.dom.Node transformedNode = result.getNode();
            final org.w3c.dom.Node transformedFirstChild = transformedNode.getFirstChild();
            if (transformedFirstChild != null && transformedFirstChild.getNodeType() == Node.ELEMENT_NODE) {
                return transformedNode;
            }

            // output is not DOM (text)
            xmlSource = new DOMSource(source.getDomNodeOrDie());
            final StringWriter writer = new StringWriter();
            final Result streamResult = new StreamResult(writer);
            transformer.transform(xmlSource, streamResult);
            return writer.toString();
        }
        catch (final Exception e) {
            throw Context.reportRuntimeError("Exception: " + e);
        }
    }
```

```diff
@@ -26,6 +26,7 @@
 
+import javax.xml.XMLConstants;
 import javax.xml.parsers.DocumentBuilderFactory;
@@ -128,6 +129,11 @@ private Object transform(final Node source) {
 
+            // By default, the JDK turns on FSP for DOM and SAX parsers and XML schema validators,
+            // which sets a number of processing limits on the processors. Conversely, by default,
+            // the JDK turns off FSP for transformers and XPath, which enables extension functions for XSLT and XPath.
+            transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
+
             final SgmlPage page = sourceDomNode.getPage();
```

## 13. GHSA-7c5v-895v-w4q5:java.lang.security.audit.object-deserialization.object-deserialization:modules/jooby-pac4j/src/main/java/io/jooby/internal/pac4j/SessionStoreImpl.java:131

- tags: on-CWE-sample, hunk
- advisory: jooby-pac4j: deserialization of untrusted data
- repo: jooby-project/jooby  commit: 3e13562cf36d7407813eae464e0f4b598de15692
- entry CWE: ['CWE-502']  finding CWEs: ['CWE-502']
- rule: object-deserialization
- finding: modules/jooby-pac4j/src/main/java/io/jooby/internal/pac4j/SessionStoreImpl.java:131 method if
- message: Found object deserialization using ObjectInputStream. Deserializing entire Java objects is dangerous because malicious actors can create Java object streams with unintended consequences. Ensure that the objects being deserialized are not user-controlled. If this must be done, consider using HMACs to sign the data stream to make sure it is not tampered with, or consider only transmitting object fields and populating a new object.

```java
public class SessionStoreImpl implements org.pac4j.core.context.session.SessionStore {

    if (value.startsWith(BIN)) {
      try {
        byte[] bytes = Base64.getDecoder().decode(value.substring(BIN.length()));
        return Optional.of(new ObjectInputStream(new ByteArrayInputStream(bytes)).readObject());
      } catch (Exception x) {
        throw SneakyThrows.propagate(x);
      }
    } else if (value.startsWith(PAC4J)) {
```

```diff
@@ -13,13 +13,10 @@
 import static io.jooby.StatusCode.UNAUTHORIZED_CODE;
+import static io.jooby.internal.pac4j.Pac4jSession.BIN;
+import static io.jooby.internal.pac4j.Pac4jSession.PAC4J;
 
-import java.io.ByteArrayInputStream;
-import java.io.ByteArrayOutputStream;
-import java.io.IOException;
-import java.io.ObjectInputStream;
-import java.io.ObjectOutputStream;
-import java.util.Base64;
+import java.io.*;
 import java.util.Optional;
@@ -35,19 +32,15 @@
 import org.pac4j.core.exception.http.WithLocationAction;
+import org.pac4j.core.util.serializer.Serializer;
 
 import io.jooby.Session;
-import io.jooby.SneakyThrows;
 import io.jooby.Value;
 
-  private static final String PAC4J = "p4j~";
-
-  private static final String BIN = "b64~";
-
   private Session getSession(WebContext context) {
@@ -75,20 +68,17 @@ public Optional<String> getSessionId(WebContext context, boolean createSession)
   public Optional<Object> get(WebContext context, String key) {
-    Optional sessionValue =
-        getSessionOrEmpty(context)
-            .map(session -> session.get(key))
-            .map(SessionStoreImpl::strToObject)
-            .orElseGet(Optional::empty);
-    return sessionValue;
+    return getSessionOrEmpty(context)
+        .map(session -> session.get(key))
+        .flatMap(value -> strToObject(context(context).require(Serializer.class), value));
   }
   public void set(WebContext context, String key, Object value) {
-    if (value == null || value.toString().length() == 0) {
+    if (value == null || value.toString().isEmpty()) {
       getSessionOrEmpty(context).ifPresent(session -> session.remove(key));
     } else {
-      String encoded = objToStr(value);
+      String encoded = objToStr(context(context).require(Serializer.class), value);
       getSession(context).put(key, encoded);
@@ -116,42 +106,31 @@ public Optional<SessionStore> buildFromTrackableSession(
   public boolean renewSession(WebContext context) {
-    getSessionOrEmpty(context).ifPresent(session -> session.renewId());
-    return true;
+    var session = getSessionOrEmpty(context);
+    session.ifPresent(Session::renewId);
+    return session.isPresent();
   }
 
-  static Optional<Object> strToObject(final Value node) {
+  static Optional<Object> strToObject(Serializer serializer, Value node) {
     if (node.isMissing()) {
     if (value.startsWith(BIN)) {
-      try {
-        byte[] bytes = Base64.getDecoder().decode(value.substring(BIN.length()));
-        return Optional.of(new ObjectInputStream(new ByteArrayInputStream(bytes)).readObject());
-      } catch (Exception x) {
-        throw SneakyThrows.propagate(x);
-      }
+      return Optional.of(serializer.deserializeFromString(value.substring(BIN.length())));
     } else if (value.startsWith(PAC4J)) {
 
-  static String objToStr(final Object value) {
+  static String objToStr(Serializer serializer, Object value) {
... (truncated)
```

## 14. GHSA-7v6m-28jr-rg84:java.lang.security.audit.el-injection.el-injection:engine/src/main/java/org/hibernate/validator/internal/engine/messageinterpolation/ElTermResolver.java:31

- tags: method-only
- advisory: Hibernate Validator may interpolate user-supplied input in a constraint violation message with Expression Language
- repo: hibernate/hibernate-validator  commit: 05f795bb7cf18856004f40e5042709e550ed0d6e
- entry CWE: ['CWE-94']  finding CWEs: ['CWE-94']
- rule: el-injection
- finding: engine/src/main/java/org/hibernate/validator/internal/engine/messageinterpolation/ElTermResolver.java:31 method 
- message: An expression is built with a dynamic value. The source of the value(s) should be verified to avoid that unfiltered values fall into this risky code evaluation.

```java
public class ElTermResolver implements TermResolver {

	private static final Log LOG = LoggerFactory.make( MethodHandles.lookup() );

	/**
	 * Name under which the currently validate value is bound to the EL context.
	 */
	private static final String VALIDATED_VALUE_NAME = "validatedValue";

	/**
	 * The locale for which to interpolate the expression.
	 */
	private final Locale locale;
```

```diff
@@ -10,23 +10,29 @@
 
+import org.hibernate.validator.internal.engine.messageinterpolation.el.BeanMethodsELContext;
+import org.hibernate.validator.internal.engine.messageinterpolation.el.BeanPropertiesElContext;
+import org.hibernate.validator.internal.engine.messageinterpolation.el.DisabledFeatureELException;
+import org.hibernate.validator.internal.engine.messageinterpolation.el.RootResolver;
+import org.hibernate.validator.internal.engine.messageinterpolation.el.VariablesELContext;
+import org.hibernate.validator.internal.util.logging.Log;
+import org.hibernate.validator.internal.util.logging.LoggerFactory;
+import org.hibernate.validator.messageinterpolation.HibernateMessageInterpolatorContext;
+
+import jakarta.el.ELContext;
 import jakarta.el.ELException;
 import jakarta.el.ExpressionFactory;
+import jakarta.el.MethodNotFoundException;
 import jakarta.el.PropertyNotFoundException;
 
-import org.hibernate.validator.internal.engine.messageinterpolation.el.RootResolver;
-import org.hibernate.validator.internal.engine.messageinterpolation.el.SimpleELContext;
-import org.hibernate.validator.internal.util.logging.Log;
-import org.hibernate.validator.internal.util.logging.LoggerFactory;
-import org.hibernate.validator.messageinterpolation.HibernateMessageInterpolatorContext;
-
 /**
  * @author Adam Stawicki
+ * @author Guillaume Smet
  */
@@ -61,14 +67,22 @@ public ElTermResolver(Locale locale, ExpressionFactory expressionFactory) {
 		String resolvedExpression = expression;
-		SimpleELContext elContext = new SimpleELContext( expressionFactory );
+
+		ELContext elContext = getElContext( context );
+
 		try {
 		}
+		catch (DisabledFeatureELException dfee) {
+			LOG.disabledFeatureInExpressionLanguage( expression, dfee );
+		}
 		catch (PropertyNotFoundException pnfe) {
 		}
+		catch (MethodNotFoundException mnfe) {
+			LOG.unknownMethodInExpressionLanguage( expression, mnfe );
+		}
 		catch (ELException e) {
@@ -79,7 +93,26 @@ public String interpolate(MessageInterpolator.Context context, String expression
 
-	private ValueExpression bindContextValues(String messageTemplate, MessageInterpolator.Context messageInterpolatorContext, SimpleELContext elContext) {
+	private ELContext getElContext(MessageInterpolator.Context context) {
+		if ( !( context instanceof HibernateMessageInterpolatorContext ) ) {
+			return new VariablesELContext( expressionFactory );
+		}
+
+		switch ( ( (HibernateMessageInterpolatorContext) context ).getExpressionLanguageFeatureLevel() ) {
+			case NONE:
+				throw LOG.expressionsNotResolvedWhenExpressionLanguageFeaturesDisabled();
+			case VARIABLES:
+				return new VariablesELContext( expressionFactory );
+			case BEAN_PROPERTIES:
+				return new BeanPropertiesElContext( expressionFactory );
+			case BEAN_METHODS:
+				return new BeanMethodsELContext( expressionFactory );
+			default:
+				throw LOG.expressionsLanguageFeatureLevelNotSupported();
+		}
+	}
+
+	private ValueExpression bindContextValues(String messageTemplate, MessageInterpolator.Context messageInterpolatorContext, ELContext elContext) {
 		// bind the validated value
@@ -104,7 +137,7 @@ private ValueExpression bindContextValues(String messageTemplate, MessageInterpo
 
... (truncated)
```

## 15. GHSA-8c3x-hq82-gjcm:java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing.documentbuilderfactory-disallow-doctype-decl-missing:org.hl7.fhir.publisher.core/src/main/java/org/hl7/fhir/igtools/publisher/Publisher.java:14317

- tags: on-CWE-sample, hunk
- advisory: XXE vulnerability in XSLT parsing in `org.hl7.fhir.publisher`
- repo: HL7/fhir-ig-publisher  commit: 3560de2f486d688a3ddcf4aa54d8bdacea380c3d
- entry CWE: ['CWE-611']  finding CWEs: ['CWE-611']
- rule: documentbuilderfactory-disallow-doctype-decl-missing
- finding: org.hl7.fhir.publisher.core/src/main/java/org/hl7/fhir/igtools/publisher/Publisher.java:14317 method loadMappingSpaces
- message: DOCTYPE declarations are enabled for this DocumentBuilderFactory. This is vulnerable to XML external entity attacks. Disable this by setting the feature "http://apache.org/xml/features/disallow-doctype-decl" to true. Alternatively, allow DOCTYPE declarations and only prohibit external entities declarations. This can be done by setting the features "http://xml.org/sax/features/external-general-entities" and "http://xml.org/sax/features/external-parameter-entities" to false.

```java
public class Publisher implements ILoggingService, IReferenceResolver, IValidationProfileUsageTracker {

  private void loadMappingSpaces(byte[] source) throws Exception {
    ByteArrayInputStream is = null;
    try {
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      factory.setNamespaceAware(true);
      DocumentBuilder builder = factory.newDocumentBuilder();
      is = new ByteArrayInputStream(source);
      Document doc = builder.parse(is);
      org.w3c.dom.Element e = XMLUtil.getFirstChild(doc.getDocumentElement());
      while (e != null) {
        MappingSpace m = new MappingSpace(XMLUtil.getNamedChild(e, "columnName").getTextContent(), XMLUtil.getNamedChild(e, "title").getTextContent(),
            XMLUtil.getNamedChild(e, "id").getTextContent(), Integer.parseInt(XMLUtil.getNamedChild(e, "sort").getTextContent()), true, false, false, XMLUtil.getNamedChild(e, "link") != null ? XMLUtil.getNamedChild(e, "link").getTextContent(): XMLUtil.getNamedChild(e, "url").getTextContent());
        mappingSpaces.put(XMLUtil.getNamedChild(e, "url").getTextContent(), m);
        org.w3c.dom.Element p = XMLUtil.getNamedChild(e, "preamble");
        if (p != null) {
          m.setPreamble(new XhtmlParser().parseHtmlNode(p).setName("div"));
        }
        e = XMLUtil.getNextSibling(e);
      }
    } catch (Exception e) {
      throw new Exception("Error processing mappingSpaces.details: "+e.getMessage(), e);
    }
  }
```

```diff
@@ -14312,7 +14312,7 @@ private String fetchCurrentIGPubVersion() {
     try {
-      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
+      DocumentBuilderFactory factory = XMLUtil.newXXEProtectedDocumentBuilderFactory();
       factory.setNamespaceAware(true);
```

## 16. GHSA-8c3x-hq82-gjcm:java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing.documentbuilderfactory-disallow-doctype-decl-missing:org.hl7.fhir.publisher.core/src/main/java/org/hl7/fhir/igtools/publisher/utils/PackageReleaser.java:844

- tags: on-CWE-sample, hunk
- advisory: XXE vulnerability in XSLT parsing in `org.hl7.fhir.publisher`
- repo: HL7/fhir-ig-publisher  commit: 3560de2f486d688a3ddcf4aa54d8bdacea380c3d
- entry CWE: ['CWE-611']  finding CWEs: ['CWE-611']
- rule: documentbuilderfactory-disallow-doctype-decl-missing
- finding: org.hl7.fhir.publisher.core/src/main/java/org/hl7/fhir/igtools/publisher/utils/PackageReleaser.java:844 method loadXml
- message: DOCTYPE declarations are enabled for this DocumentBuilderFactory. This is vulnerable to XML external entity attacks. Disable this by setting the feature "http://apache.org/xml/features/disallow-doctype-decl" to true. Alternatively, allow DOCTYPE declarations and only prohibit external entities declarations. This can be done by setting the features "http://xml.org/sax/features/external-general-entities" and "http://xml.org/sax/features/external-parameter-entities" to false.

```java
public class PackageReleaser {

  private Document loadXml(File file) throws Exception {
    InputStream src = new FileInputStream(file);
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    DocumentBuilder db = dbf.newDocumentBuilder();
    return db.parse(src);
  }
```

```diff
@@ -840,7 +840,7 @@ private void check(boolean condition, String message) {
     InputStream src = new FileInputStream(file);
-    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
+    DocumentBuilderFactory dbf = XMLUtil.newXXEProtectedDocumentBuilderFactory();
     DocumentBuilder db = dbf.newDocumentBuilder();
```

## 17. GHSA-8c3x-hq82-gjcm:java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing.documentbuilderfactory-disallow-doctype-decl-missing:org.hl7.fhir.publisher.core/src/main/java/org/hl7/fhir/igtools/publisher/utils/TemplateReleaser.java:605

- tags: on-CWE-sample, hunk
- advisory: XXE vulnerability in XSLT parsing in `org.hl7.fhir.publisher`
- repo: HL7/fhir-ig-publisher  commit: 3560de2f486d688a3ddcf4aa54d8bdacea380c3d
- entry CWE: ['CWE-611']  finding CWEs: ['CWE-611']
- rule: documentbuilderfactory-disallow-doctype-decl-missing
- finding: org.hl7.fhir.publisher.core/src/main/java/org/hl7/fhir/igtools/publisher/utils/TemplateReleaser.java:605 method loadXml
- message: DOCTYPE declarations are enabled for this DocumentBuilderFactory. This is vulnerable to XML external entity attacks. Disable this by setting the feature "http://apache.org/xml/features/disallow-doctype-decl" to true. Alternatively, allow DOCTYPE declarations and only prohibit external entities declarations. This can be done by setting the features "http://xml.org/sax/features/external-general-entities" and "http://xml.org/sax/features/external-parameter-entities" to false.

```java
public class TemplateReleaser {

  private Document loadXml(File file) throws Exception {
    InputStream src = new FileInputStream(file);
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    DocumentBuilder db = dbf.newDocumentBuilder();
    return db.parse(src);
  }
```

```diff
@@ -601,7 +601,7 @@ private void check(boolean condition, String message) {
     InputStream src = new FileInputStream(file);
-    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
+    DocumentBuilderFactory dbf = XMLUtil.newXXEProtectedDocumentBuilderFactory();
     DocumentBuilder db = dbf.newDocumentBuilder();
```

## 18. GHSA-8gqp-hr9g-pg62:java.lang.security.audit.script-engine-injection.script-engine-injection:conductor-clients/java/conductor-java-sdk/sdk/src/main/java/com/netflix/conductor/sdk/workflow/def/tasks/Javascript.java:102

- tags: off-CWE, hunk
- advisory: Conductor vulnerable to OS command injection through unrestricted access to Java classes
- repo: conductor-oss/conductor  commit: e9816501df1e364a3d39d7fe37d6e167c40eaa1b
- entry CWE: ['CWE-78']  finding CWEs: ['CWE-94']
- rule: script-engine-injection
- finding: conductor-clients/java/conductor-java-sdk/sdk/src/main/java/com/netflix/conductor/sdk/workflow/def/tasks/Javascript.java:102 method validate
- message: Detected potential code injection using ScriptEngine. Ensure user-controlled data cannot enter '.eval()', otherwise, this is a code injection vulnerability.

```java
public class Javascript extends Task<Javascript> {

    public Javascript validate() {
        ScriptEngine scriptEngine = new ScriptEngineManager().getEngineByName(ENGINE);
        if (scriptEngine == null) {
            LOGGER.error("missing " + ENGINE + " engine.  Ensure you are running supported JVM");
            return this;
        }

        try {

            Bindings bindings = scriptEngine.createBindings();
            bindings.put("$", new HashMap<>());
            scriptEngine.eval(getExpression(), bindings);

        } catch (ScriptException e) {
            String message = e.getMessage();
            throw new ValidationError(message);
        }
        return this;
    }
```

```diff
@@ -19,9 +19,9 @@
 import javax.script.ScriptEngine;
-import javax.script.ScriptEngineManager;
 import javax.script.ScriptException;
 
+import org.openjdk.nashorn.api.scripting.NashornScriptEngineFactory;
 import org.slf4j.Logger;
@@ -100,7 +100,7 @@ public String getExpression() {
     public Javascript validate() {
-        ScriptEngine scriptEngine = new ScriptEngineManager().getEngineByName(ENGINE);
+        ScriptEngine scriptEngine = new NashornScriptEngineFactory().getScriptEngine("--no-java");
         if (scriptEngine == null) {
@@ -128,7 +128,7 @@ public Javascript validate() {
 
-        ScriptEngine scriptEngine = new ScriptEngineManager().getEngineByName(ENGINE);
+        ScriptEngine scriptEngine = new NashornScriptEngineFactory().getScriptEngine("--no-java");
         if (scriptEngine == null) {
```

## 19. GHSA-8gqp-hr9g-pg62:java.lang.security.audit.script-engine-injection.script-engine-injection:conductor-clients/java/conductor-java-sdk/sdk/src/main/java/com/netflix/conductor/sdk/workflow/def/tasks/Javascript.java:129

- tags: off-CWE, hunk
- advisory: Conductor vulnerable to OS command injection through unrestricted access to Java classes
- repo: conductor-oss/conductor  commit: e9816501df1e364a3d39d7fe37d6e167c40eaa1b
- entry CWE: ['CWE-78']  finding CWEs: ['CWE-94']
- rule: script-engine-injection
- finding: conductor-clients/java/conductor-java-sdk/sdk/src/main/java/com/netflix/conductor/sdk/workflow/def/tasks/Javascript.java:129 method test
- message: Detected potential code injection using ScriptEngine. Ensure user-controlled data cannot enter '.eval()', otherwise, this is a code injection vulnerability.

```java
public class Javascript extends Task<Javascript> {

    public Object test(Map<String, Object> input) {

        ScriptEngine scriptEngine = new ScriptEngineManager().getEngineByName(ENGINE);
        if (scriptEngine == null) {
            LOGGER.error("missing " + ENGINE + " engine.  Ensure you are running supported JVM");
            return this;
        }

        try {

            Bindings bindings = scriptEngine.createBindings();
            bindings.put("$", input);
            return scriptEngine.eval(getExpression(), bindings);

        } catch (ScriptException e) {
            String message = e.getMessage();
            throw new ValidationError(message);
        }
    }
```

```diff
@@ -19,9 +19,9 @@
 import javax.script.ScriptEngine;
-import javax.script.ScriptEngineManager;
 import javax.script.ScriptException;
 
+import org.openjdk.nashorn.api.scripting.NashornScriptEngineFactory;
 import org.slf4j.Logger;
@@ -100,7 +100,7 @@ public String getExpression() {
     public Javascript validate() {
-        ScriptEngine scriptEngine = new ScriptEngineManager().getEngineByName(ENGINE);
+        ScriptEngine scriptEngine = new NashornScriptEngineFactory().getScriptEngine("--no-java");
         if (scriptEngine == null) {
@@ -128,7 +128,7 @@ public Javascript validate() {
 
-        ScriptEngine scriptEngine = new ScriptEngineManager().getEngineByName(ENGINE);
+        ScriptEngine scriptEngine = new NashornScriptEngineFactory().getScriptEngine("--no-java");
         if (scriptEngine == null) {
```

## 20. GHSA-54wc-49qj-5ghj:java.lang.security.audit.crypto.use-of-md5.use-of-md5:src/main/java/net/mingsoft/cms/action/BaseAction.java:157

- tags: off-CWE, hunk
- advisory: MCMS vulnerable SQL injection via the content_title parameter
- repo: ming-soft/MCMS  commit: 35ccbf1e3d38ab6aa178524a47c38dff6b448b59
- entry CWE: ['CWE-89']  finding CWEs: ['CWE-328']
- rule: use-of-md5
- finding: src/main/java/net/mingsoft/cms/action/BaseAction.java:157 method exec
- message: Detected MD5 hash algorithm which is considered insecure. MD5 is not collision resistant and is therefore not suitable as a cryptographic signature. Use HMAC instead.

```java
public class BaseAction extends BaseFileAction {

    public String exec(HttpServletRequest request, MultipartFile upfile, Map execFileConfigMap, String version){
        String uploadFolderPath = MSProperties.upload.path;
        String uploadMapping = MSProperties.upload.mapping;

        Map uploadConfig = ConfigUtil.getMap("文件上传配置");
        if (MapUtil.isNotEmpty(uploadConfig)){
            uploadFolderPath = uploadConfig.get("uploadPath").toString();
            uploadMapping = uploadConfig.get("uploadMapping").toString();
        }

        // 获取真实完整上传路径
        String rootPath = FileUtil.isAbsolutePath(uploadFolderPath) ? uploadFolderPath : BasicUtil.getRealPath(uploadFolderPath);

        Map execConfigMap = new HashMap();
        execConfigMap.putAll(execFileConfigMap);

        AppEntity app = BasicUtil.getApp();

        String datePath = DateUtil.format(new Date(), "yyyyMMdd");

        // /appId/editor/yyyyMMdd/{time}
        String uploadPath = "/".concat(app.getAppId()).concat("/editor/").concat(datePath).concat("/");

        String filePathFormat = uploadPath.concat("{time}");



        execConfigMap.put("imagePathFormat", filePathFormat);
        execConfigMap.put("filePathFormat", filePathFormat);
        execConfigMap.put("videoPathFormat", filePathFormat);
        execConfigMap.put("catcherPathFormat", filePathFormat);
        execConfigMap.put("scrawlPathFormat", filePathFormat);
        execConfigMap.put("snapscreenPathFormat", filePathFormat);

        String execConfig = JSONUtil.toJsonStr(execConfigMap);

        // 如果upfile不为空，说明此处操作时上传附件操作
        if (upfile != null){
            State state = null;
            String upFileMainName = FileNameUtil.mainName(upfile.getOriginalFilename());
            if (StringUtils.isBlank(upFileMainName)){
                return new BaseState(false, getResString("err.error",getResString("file.name"))).toJSONString();
            }
            // 组装uploadConfigBean上传使用
            UploadConfigBean bean = new UploadConfigBean(uploadPath, upfile, null, true);
            bean.setFileSize(upfile.getSize());
            bean.setFileName(upfile.getOriginalFilename());
            try {
                // 判断是依赖ms-file插件
                String type = ConfigUtil.getString("存储设置", "storeSelect");
                IUploadBaseService uploadBaseService = null;
                if (StringUtils.isNotBlank(type)) {
                    // 单个文件上传计算下各个参数值避免重复上传
                    if (StringUtils.isBlank(bean.getFileIdentifier())){
                        try {
                            bean.setFileIdentifier(String.valueOf(Hex.encodeHex(MessageDigest.getInstance("MD5").digest(bean.getFile().getBytes()))));
                        } catch (NoSuchAlgorithmException e) {
                            e.printStackTrace();
                        }
                    }
                    //ms-file 插件启用
                    uploadBaseService = (IUploadBaseService) SpringUtil.getBean(type);
                }
                ResultData resultData = null;
                // 根据不同类型决定上传逻辑
                if (uploadBaseService != null) {
                    resultData = uploadBaseService.upload(bean);
                } else {
                    resultData = this.upload(bean);
                }
                if (resultData.isSuccess()) {
                    // 组装百度编辑器格式
                    state = new BaseState(true);
                    state.putInfo("original", upfile.getOriginalFilename());
                    state.putInfo("size", upfile.getSize());
                    state.putInfo("title", FileNameUtil.getName(resultData.getData(String.class)));
                    state.putInfo("type", "." + FileNameUtil.getSuffix(upfile.getOriginalFilename()));
                    // 由于百度编辑器不是正常的uploadConfigBean，是无法正常通过getFileIdentifier获取到文件标识的，所以在这里做一个容错处理
                    state.putInfo("fileIdentifier", bean.getFileIdentifier());
                    // 判断是否有contentPath
                    String contextPath = BasicUtil.getContextPath();
                    String filePath = resultData.getData(String.class);
                    if (StringUtils.isNotBlank(filePath) && !filePath.startsWith("http")) {
                        filePath = (contextPath.equals("/") ? "" : contextPath) + filePath;
                    }
                    state.putInfo("url", filePath);
                } else {
                    state = new BaseState(false, resultData.getMsg());
... (truncated)
```

```diff
@@ -21,11 +21,14 @@
 package net.mingsoft.cms.action;
+
 import cn.hutool.core.date.DateUtil;
 import cn.hutool.core.util.StrUtil;
+import cn.hutool.json.JSONArray;
+import cn.hutool.json.JSONObject;
 import cn.hutool.json.JSONUtil;
@@ -49,10 +52,7 @@
 import java.security.NoSuchAlgorithmException;
-import java.util.Date;
-import java.util.HashMap;
-import java.util.Map;
-import java.util.MissingResourceException;
+import java.util.*;
 
@@ -150,15 +150,15 @@ public String exec(HttpServletRequest request, MultipartFile upfile, Map execFil
                 IUploadBaseService uploadBaseService = null;
-                if (StringUtils.isNotBlank(type)) {
-                    // 单个文件上传计算下各个参数值避免重复上传
-                    if (StringUtils.isBlank(bean.getFileIdentifier())){
-                        try {
-                            bean.setFileIdentifier(String.valueOf(Hex.encodeHex(MessageDigest.getInstance("MD5").digest(bean.getFile().getBytes()))));
-                        } catch (NoSuchAlgorithmException e) {
-                            e.printStackTrace();
-                        }
+                // 单个文件上传计算下各个参数值避免重复上传
+                if (StringUtils.isBlank(bean.getFileIdentifier())){
+                    try {
+                        bean.setFileIdentifier(String.valueOf(Hex.encodeHex(MessageDigest.getInstance("MD5").digest(bean.getFile().getBytes()))));
+                    } catch (NoSuchAlgorithmException e) {
+                        e.printStackTrace();
                     }
+                }
+                if (StringUtils.isNotBlank(type)) {
                     //ms-file 插件启用
@@ -201,8 +201,30 @@ public String exec(HttpServletRequest request, MultipartFile upfile, Map execFil
         String result = actionEnter.exec();
+        // 获取请求类型
+        String action = BasicUtil.getString("action");
         Map jsonMap = JSONUtil.toBean(result,Map.class);
-        jsonMap.put("url","/".concat(uploadMapping.replaceAll("/([\\s\\S]*)/\\*\\*",  "$1")).concat(jsonMap.get("url")+""));
+        // 这里会有图片复制粘贴情况
+        if ("catchimage".equalsIgnoreCase(action) && jsonMap.get("state").equals("SUCCESS")) {
+            // 处理绝对路径和项目名情况
+            JSONArray fileUrls = JSONUtil.parseArray(MapUtil.getStr(jsonMap, "list", "[]"));
+            String url = "";
+            List<JSONObject> list = new ArrayList<>();
+            // 循环上传文件，判断是否有项目名和绝对路径
+            for (Object fileUrl : fileUrls) {
+                JSONObject jsonObject = (JSONObject) fileUrl;
+                url = jsonObject.getStr("url");
+                // 判断是否有contentPath
+                String contextPath = BasicUtil.getContextPath();
+                if (StringUtils.isNotBlank(url) && !url.startsWith("http")) {
+                    url = "/".concat(uploadMapping.replaceAll("/([\\s\\S]*)/\\*\\*", "$1")).concat(url + "");
+                    url = (contextPath.equals("/") ? "" : contextPath) + url;
+                }
+                jsonObject.set("url", url);
+                list.add(jsonObject);
+            }
+            jsonMap.put("list", list);
+        }
         return JSONUtil.toJsonStr(jsonMap);
```

## 21. GHSA-65hj-9ppw-77xc:java.lang.security.audit.crlf-injection-logs.crlf-injection-logs:ff4j-web/src/main/java/org/ff4j/web/embedded/ConsoleOperations.java:87

- tags: off-CWE, method-only
- advisory: ff4j is vulnerable to Remote Code Execution (RCE)
- repo: ff4j/ff4j  commit: 62d03140f3bfbd380d0f4b4e5a94dcb8baa9d9c6
- entry CWE: ['CWE-94']  finding CWEs: ['CWE-93']
- rule: crlf-injection-logs
- finding: ff4j-web/src/main/java/org/ff4j/web/embedded/ConsoleOperations.java:87 method createFeature
- message: When data from an untrusted source is put into a logger and not neutralized correctly, an attacker could forge log entries or include malicious content.

```java
public final class ConsoleOperations {

    public static void createFeature(FF4j ff4j, HttpServletRequest req) {
        // uid
        final String featureId = req.getParameter(FEATID);
        if (featureId != null && !featureId.isEmpty()) {
            Feature fp = new Feature(featureId, false);

            // Description
            final String featureDesc = req.getParameter(DESCRIPTION);
            if (null != featureDesc && !featureDesc.isEmpty()) {
                fp.setDescription(featureDesc);
            }

            // GroupName
            final String groupName = req.getParameter(GROUPNAME);
            if (null != groupName && !groupName.isEmpty()) {
                fp.setGroup(groupName);
            }

            // Strategy
            final String strategy = req.getParameter(STRATEGY);
            if (null != strategy && !strategy.isEmpty()) {
                try {
                    Class<?> strategyClass = Class.forName(strategy);
                    FlippingStrategy fstrategy = (FlippingStrategy) strategyClass.newInstance();

                    final String strategyParams = req.getParameter(STRATEGY_INIT);
                    if (null != strategyParams && !strategyParams.isEmpty()) {
                        Map<String, String> initParams = new HashMap<String, String>();
                        String[] params = strategyParams.split(";");
                        for (String currentP : params) {
                            String[] cur = currentP.split("=");
                            if (cur.length < 2) {
                                throw new IllegalArgumentException("Invalid Syntax : param1=val1,val2;param2=val3,val4");
                            }
                            initParams.put(cur[0], cur[1]);
                        }
                        fstrategy.init(featureId, initParams);
                    }
                    fp.setFlippingStrategy(fstrategy);

                } catch (ClassNotFoundException e) {
                    throw new IllegalArgumentException("Cannot find strategy class", e);
                } catch (InstantiationException e) {
                    throw new IllegalArgumentException("Cannot instantiate strategy", e);
                } catch (IllegalAccessException e) {
                    throw new IllegalArgumentException("Cannot instantiate : no public constructor", e);
                }
            }

            // Permissions
            final String permission = req.getParameter(PERMISSION);
            if (null != permission && PERMISSION_RESTRICTED.equals(permission)) {
                @SuppressWarnings("unchecked")
                Map<String, Object> parameters = req.getParameterMap();
                Set<String> permissions = new HashSet<String>();
                for (String key : parameters.keySet()) {
                    if (key.startsWith(PREFIX_CHECKBOX)) {
                        permissions.add(key.replace(PREFIX_CHECKBOX, ""));
                    }
                }
                fp.setPermissions(permissions);
            }

            // Creation
            ff4j.getFeatureStore().create(fp);
            LOGGER.info(featureId + " has been created");
        }
    }
```

```diff
@@ -105,6 +105,9 @@ public static void createFeature(FF4j ff4j, HttpServletRequest req) {
                     Class<?> strategyClass = Class.forName(strategy);
+                    if (!FlippingStrategy.class.isAssignableFrom(strategyClass)) {
+                        throw new IllegalArgumentException("Cannot create flipstrategy: <" + strategy + "> invalid type");
+                    }
                     FlippingStrategy fstrategy = (FlippingStrategy) strategyClass.newInstance();
@@ -246,6 +249,9 @@ private static void updateFlippingStrategy(Feature fp, String strategy, String s
                 Class<?> strategyClass = Class.forName(strategy);
+                if (!FlippingStrategy.class.isAssignableFrom(strategyClass)) {
+                    throw new IllegalArgumentException("Cannot create flipstrategy <" + strategy + "> invalid type");
+                }
                 FlippingStrategy fstrategy = (FlippingStrategy) strategyClass.newInstance();
```

## 22. GHSA-83w4-x5w9-hf4h:java.spring.security.unrestricted-request-mapping.unrestricted-request-mapping:xxl-job-admin/src/main/java/com/xxl/job/admin/controller/JobLogController.java:138

- tags: off-CWE, hunk
- advisory: XXL-JOB vulnerable to Server-Side Request Forgery (SSRF)
- repo: xuxueli/xxl-job  commit: 9293c61ca0a8d54afdfb27cc568885ae639a14dc
- entry CWE: ['CWE-918']  finding CWEs: ['CWE-352']
- rule: unrestricted-request-mapping
- finding: xxl-job-admin/src/main/java/com/xxl/job/admin/controller/JobLogController.java:138 method 
- message: Detected a method annotated with 'RequestMapping' that does not specify the HTTP method. CSRF protections are not enabled for GET, HEAD, TRACE, or OPTIONS, and by default all HTTP methods are allowed when the HTTP method is not explicitly specified. This means that a method that performs state changes could be vulnerable to CSRF attacks. To mitigate, add the 'method' field and specify the HTTP method (such as 'RequestMethod.POST').

```java
package com.xxl.job.admin.controller;
import com.xxl.job.admin.core.exception.XxlJobException;
import com.xxl.job.admin.core.complete.XxlJobCompleter;
import com.xxl.job.admin.core.model.XxlJobGroup;
import com.xxl.job.admin.core.model.XxlJobInfo;
import com.xxl.job.admin.core.model.XxlJobLog;
import com.xxl.job.admin.core.scheduler.XxlJobScheduler;
import com.xxl.job.admin.core.util.I18nUtil;
import com.xxl.job.admin.dao.XxlJobGroupDao;
import com.xxl.job.admin.dao.XxlJobInfoDao;
import com.xxl.job.admin.dao.XxlJobLogDao;
import com.xxl.job.core.biz.ExecutorBiz;
import com.xxl.job.core.biz.model.KillParam;
import com.xxl.job.core.biz.model.LogParam;
import com.xxl.job.core.biz.model.LogResult;
import com.xxl.job.core.biz.model.ReturnT;
import com.xxl.job.core.util.DateUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

		if (jobLog == null) {
            throw new RuntimeException(I18nUtil.getString("joblog_logid_unvalid"));
		}

        model.addAttribute("triggerCode", jobLog.getTriggerCode());
        model.addAttribute("handleCode", jobLog.getHandleCode());
        model.addAttribute("executorAddress", jobLog.getExecutorAddress());
        model.addAttribute("triggerTime", jobLog.getTriggerTime().getTime());
        model.addAttribute("logId", jobLog.getId());
		return "joblog/joblog.detail";
	}

	@RequestMapping("/logDetailCat")
	@ResponseBody
	public ReturnT<LogResult> logDetailCat(String executorAddress, long triggerTime, long logId, int fromLineNum){
		try {
			ExecutorBiz executorBiz = XxlJobScheduler.getExecutorBiz(executorAddress);
			ReturnT<LogResult> logResult = executorBiz.log(new LogParam(triggerTime, logId, fromLineNum));

			// is end
            if (logResult.getContent()!=null && logResult.getContent().getFromLineNum() > logResult.getContent().getToLineNum()) {
                XxlJobLog jobLog = xxlJobLogDao.load(logId);
                if (jobLog.getHandleCode() > 0) {
                    logResult.getContent().setEnd(true);
                }
```

```diff
@@ -1,7 +1,7 @@
 
-import com.xxl.job.admin.core.exception.XxlJobException;
 import com.xxl.job.admin.core.complete.XxlJobCompleter;
+import com.xxl.job.admin.core.exception.XxlJobException;
 import com.xxl.job.admin.core.model.XxlJobGroup;
@@ -129,22 +129,26 @@ public String logDetailPage(int id, Model model){
         model.addAttribute("handleCode", jobLog.getHandleCode());
-        model.addAttribute("executorAddress", jobLog.getExecutorAddress());
-        model.addAttribute("triggerTime", jobLog.getTriggerTime().getTime());
         model.addAttribute("logId", jobLog.getId());
 	@ResponseBody
-	public ReturnT<LogResult> logDetailCat(String executorAddress, long triggerTime, long logId, int fromLineNum){
+	public ReturnT<LogResult> logDetailCat(long logId, int fromLineNum){
 		try {
-			ExecutorBiz executorBiz = XxlJobScheduler.getExecutorBiz(executorAddress);
-			ReturnT<LogResult> logResult = executorBiz.log(new LogParam(triggerTime, logId, fromLineNum));
+			// valid
+			XxlJobLog jobLog = xxlJobLogDao.load(logId);	// todo, need to improve performance
+			if (jobLog == null) {
+				return new ReturnT<LogResult>(ReturnT.FAIL_CODE, I18nUtil.getString("joblog_logid_unvalid"));
+			}
+
+			// log cat
+			ExecutorBiz executorBiz = XxlJobScheduler.getExecutorBiz(jobLog.getExecutorAddress());
+			ReturnT<LogResult> logResult = executorBiz.log(new LogParam(jobLog.getTriggerTime().getTime(), logId, fromLineNum));
 
             if (logResult.getContent()!=null && logResult.getContent().getFromLineNum() > logResult.getContent().getToLineNum()) {
-                XxlJobLog jobLog = xxlJobLogDao.load(logId);
                 if (jobLog.getHandleCode() > 0) {
```

## 23. GHSA-763j-q7wv-vf3m:java.lang.security.audit.unvalidated-redirect.unvalidated-redirect:dspace-jspui/src/main/java/org/dspace/app/webui/servlet/ControlledVocabularyServlet.java:31

- tags: on-CWE-sample, hunk
- advisory: JSPUI's controlled vocabulary feature vulnerable to Open Redirect before v6.4 and v5.11
- repo: DSpace/DSpace  commit: 5f72424a478f59061dcc516b866dcc687bc3f9de
- entry CWE: ['CWE-601']  finding CWEs: ['CWE-601']
- rule: unvalidated-redirect
- finding: dspace-jspui/src/main/java/org/dspace/app/webui/servlet/ControlledVocabularyServlet.java:31 method doDSGet
- message: Application redirects to a destination URL specified by a user-supplied parameter that is not validated. This could direct users to malicious locations. Consider using an allowlist to validate URLs.

```java
public class ControlledVocabularyServlet extends DSpaceServlet
{

    protected void doDSGet(Context context, HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException,
            SQLException, AuthorizeException
    {

        String ID = "";
        String filter = "";
        String callerUrl = request.getParameter("callerUrl");

        if (request.getParameter("ID") != null)
        {
            ID = request.getParameter("ID");
        }

        if (request.getParameter("filter") != null)
        {
            filter = request.getParameter("filter");
        }

        request.getSession()
                .setAttribute("controlledvocabulary.filter", filter);
        request.getSession().setAttribute("controlledvocabulary.ID", ID);
        response.sendRedirect(callerUrl);
    }
```

```diff
@@ -14,6 +14,7 @@
 
+import org.apache.log4j.Logger;
 import org.dspace.authorize.AuthorizeException;
@@ -25,8 +26,8 @@
 {
-    // private static Logger log =
-    // Logger.getLogger(ControlledVocabularyServlet.class);
+    private static Logger log =
+    Logger.getLogger(ControlledVocabularyServlet.class);
 
@@ -37,6 +38,13 @@ protected void doDSGet(Context context, HttpServletRequest request,
 
+        // callerUrl must starts with URL outside DSpace request context path
+        if(!callerUrl.startsWith(request.getContextPath())) {
+            log.error("Controlled vocabulary caller URL would result in redirect outside DSpace web app: " + callerUrl + ". Rejecting request with 400 Bad Request.");
+            response.sendError(400, "The caller URL must be within the DSpace base URL of " + request.getContextPath());
+            return;
+        }
+
         if (request.getParameter("ID") != null)
```

## 24. GHSA-763j-q7wv-vf3m:java.lang.security.audit.tainted-session-from-http-request.tainted-session-from-http-request:dspace-jspui/src/main/java/org/dspace/app/webui/servlet/ControlledVocabularyServlet.java:51

- tags: off-CWE, method-only
- advisory: JSPUI's controlled vocabulary feature vulnerable to Open Redirect before v6.4 and v5.11
- repo: DSpace/DSpace  commit: 5f72424a478f59061dcc516b866dcc687bc3f9de
- entry CWE: ['CWE-601']  finding CWEs: ['CWE-501']
- rule: tainted-session-from-http-request
- finding: dspace-jspui/src/main/java/org/dspace/app/webui/servlet/ControlledVocabularyServlet.java:51 method doDSGet
- message: Detected input from a HTTPServletRequest going into a session command, like `setAttribute`. User input into such a command could lead to an attacker inputting malicious code into your session parameters, blurring the line between what's trusted and untrusted, and therefore leading to a trust boundary violation. This could lead to programmers trusting unvalidated data. Instead, thoroughly sanitize user input before passing it into such function calls.

```java
public class ControlledVocabularyServlet extends DSpaceServlet
{

    protected void doDSGet(Context context, HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException,
            SQLException, AuthorizeException
    {

        String ID = "";
        String filter = "";
        String callerUrl = request.getParameter("callerUrl");

        if (request.getParameter("ID") != null)
        {
            ID = request.getParameter("ID");
        }

        if (request.getParameter("filter") != null)
        {
            filter = request.getParameter("filter");
        }

        request.getSession()
                .setAttribute("controlledvocabulary.filter", filter);
        request.getSession().setAttribute("controlledvocabulary.ID", ID);
        response.sendRedirect(callerUrl);
    }
```

```diff
@@ -14,6 +14,7 @@
 
+import org.apache.log4j.Logger;
 import org.dspace.authorize.AuthorizeException;
@@ -25,8 +26,8 @@
 {
-    // private static Logger log =
-    // Logger.getLogger(ControlledVocabularyServlet.class);
+    private static Logger log =
+    Logger.getLogger(ControlledVocabularyServlet.class);
 
@@ -37,6 +38,13 @@ protected void doDSGet(Context context, HttpServletRequest request,
 
+        // callerUrl must starts with URL outside DSpace request context path
+        if(!callerUrl.startsWith(request.getContextPath())) {
+            log.error("Controlled vocabulary caller URL would result in redirect outside DSpace web app: " + callerUrl + ". Rejecting request with 400 Bad Request.");
+            response.sendError(400, "The caller URL must be within the DSpace base URL of " + request.getContextPath());
+            return;
+        }
+
         if (request.getParameter("ID") != null)
```

## 25. GHSA-763j-q7wv-vf3m:java.lang.security.audit.tainted-session-from-http-request.tainted-session-from-http-request:dspace-jspui/src/main/java/org/dspace/app/webui/servlet/ControlledVocabularyServlet.java:52

- tags: off-CWE, method-only
- advisory: JSPUI's controlled vocabulary feature vulnerable to Open Redirect before v6.4 and v5.11
- repo: DSpace/DSpace  commit: 5f72424a478f59061dcc516b866dcc687bc3f9de
- entry CWE: ['CWE-601']  finding CWEs: ['CWE-501']
- rule: tainted-session-from-http-request
- finding: dspace-jspui/src/main/java/org/dspace/app/webui/servlet/ControlledVocabularyServlet.java:52 method doDSGet
- message: Detected input from a HTTPServletRequest going into a session command, like `setAttribute`. User input into such a command could lead to an attacker inputting malicious code into your session parameters, blurring the line between what's trusted and untrusted, and therefore leading to a trust boundary violation. This could lead to programmers trusting unvalidated data. Instead, thoroughly sanitize user input before passing it into such function calls.

```java
public class ControlledVocabularyServlet extends DSpaceServlet
{

    protected void doDSGet(Context context, HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException,
            SQLException, AuthorizeException
    {

        String ID = "";
        String filter = "";
        String callerUrl = request.getParameter("callerUrl");

        if (request.getParameter("ID") != null)
        {
            ID = request.getParameter("ID");
        }

        if (request.getParameter("filter") != null)
        {
            filter = request.getParameter("filter");
        }

        request.getSession()
                .setAttribute("controlledvocabulary.filter", filter);
        request.getSession().setAttribute("controlledvocabulary.ID", ID);
        response.sendRedirect(callerUrl);
    }
```

```diff
@@ -14,6 +14,7 @@
 
+import org.apache.log4j.Logger;
 import org.dspace.authorize.AuthorizeException;
@@ -25,8 +26,8 @@
 {
-    // private static Logger log =
-    // Logger.getLogger(ControlledVocabularyServlet.class);
+    private static Logger log =
+    Logger.getLogger(ControlledVocabularyServlet.class);
 
@@ -37,6 +38,13 @@ protected void doDSGet(Context context, HttpServletRequest request,
 
+        // callerUrl must starts with URL outside DSpace request context path
+        if(!callerUrl.startsWith(request.getContextPath())) {
+            log.error("Controlled vocabulary caller URL would result in redirect outside DSpace web app: " + callerUrl + ". Rejecting request with 400 Bad Request.");
+            response.sendError(400, "The caller URL must be within the DSpace base URL of " + request.getContextPath());
+            return;
+        }
+
         if (request.getParameter("ID") != null)
```

## 26. GHSA-f5h9-qx38-2hgp:java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing.documentbuilderfactory-disallow-doctype-decl-missing:aws-android-sdk-core/src/main/java/com/amazonaws/regions/RegionMetadataParser.java:115

- tags: off-CWE, hunk
- advisory: AWS SDK is vulnerable to server-side request forgery (SSRF) 
- repo: aws-amplify/aws-sdk-android  commit: c3e6d69422e1f0c80fe53f2d757b8df97619af2b
- entry CWE: ['CWE-918']  finding CWEs: ['CWE-611']
- rule: documentbuilderfactory-disallow-doctype-decl-missing
- finding: aws-android-sdk-core/src/main/java/com/amazonaws/regions/RegionMetadataParser.java:115 method internalParse
- message: DOCTYPE declarations are enabled for this DocumentBuilderFactory. This is vulnerable to XML external entity attacks. Disable this by setting the feature "http://apache.org/xml/features/disallow-doctype-decl" to true. Alternatively, allow DOCTYPE declarations and only prohibit external entities declarations. This can be done by setting the features "http://xml.org/sax/features/external-general-entities" and "http://xml.org/sax/features/external-parameter-entities" to false.

```java
public class RegionMetadataParser {

    private static List<Region> internalParse(
            final InputStream input,
            final boolean endpointVerification) throws IOException {

        Document document;
        try {

            DocumentBuilderFactory factory =
                    DocumentBuilderFactory.newInstance();

            DocumentBuilder documentBuilder = factory.newDocumentBuilder();
            document = documentBuilder.parse(input);

        } catch (IOException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new IOException("Unable to parse region metadata file: "
                    + exception.getMessage(),
                    exception);
        } finally {
            try {
                input.close();
            } catch (IOException exception) {
            }
        }

        NodeList regionNodes = document.getElementsByTagName(REGION_TAG);
        List<Region> regions = new ArrayList<Region>();
        for (int i = 0; i < regionNodes.getLength(); i++) {
            Node node = regionNodes.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE) {
                Element element = (Element) node;
                regions.add(parseRegionElement(element, endpointVerification));
            }
        }

        return regions;
    }
```

```diff
@@ -109,9 +109,10 @@ private static List<Region> internalParse(
 
-            DocumentBuilderFactory factory =
-                    DocumentBuilderFactory.newInstance();
-
+            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
+            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
+            factory.setXIncludeAware(false);
+            factory.setExpandEntityReferences(false);
             DocumentBuilder documentBuilder = factory.newDocumentBuilder();
```

## 27. GHSA-f63g-88cj-hjf9:java.lang.security.audit.object-deserialization.object-deserialization:izpack-installer/src/main/java/com/izforge/izpack/installer/unpacker/UnpackerBase.java:312

- tags: off-CWE, method-only
- advisory: IzPack has Path Traversal in UnpackerBase that allows writing files outside the installation directory via malicious pack entries
- repo: izpack/izpack  commit: 4233ba38d0f1825f9cf3e0204e5261a5498e29d8
- entry CWE: ['CWE-22']  finding CWEs: ['CWE-502']
- rule: object-deserialization
- finding: izpack-installer/src/main/java/com/izforge/izpack/installer/unpacker/UnpackerBase.java:312 method unpack
- message: Found object deserialization using ObjectInputStream. Deserializing entire Java objects is dangerous because malicious actors can create Java object streams with unintended consequences. Ensure that the objects being deserialized are not user-controlled. If this must be done, consider using HMACs to sign the data stream to make sure it is not tampered with, or consider only transmitting object fields and populating a new object.

```java
public abstract class UnpackerBase implements IUnpacker
{

    public void unpack()
    {
        logIntro();

        state = State.UNPACKING;
        ObjectInputStream objIn = null;
        try
        {
            FileQueue queue = queueFactory.isSupported() ? queueFactory.create() : null;

            InputStream in = resources.getInputStream("packs.info");
            objIn = new ObjectInputStream(in);
            @SuppressWarnings("unchecked") List<PackInfo> packsInfo = (List<PackInfo>) objIn.readObject();
            objIn.close();

            selectedPacks = installData.getSelectedPacks();

            preUnpack(selectedPacks);
            unpack(packsInfo, queue);
            postUnpack(selectedPacks, queue);
        }
        catch (Exception exception)
        {
            setResult(false);
            logger.log(Level.SEVERE, exception.getMessage(), exception);

            listener.stopAction();

            if (exception instanceof ResourceInterruptedException)
            {
                prompt.message(Type.INFORMATION, messages.get("installer.cancelled"));
            } else
            {
                IzPackException ize;
                if (exception instanceof InstallerException)
                {
                    InstallerException ie = (InstallerException) exception;
                    Throwable t = ie.getCause();
                    ize = new IzPackException(messages.get("installer.errorMessage"),
                            t != null ? t : exception);
                } else if (exception instanceof IzPackException)
                {
                    ize = (IzPackException) exception;
                } else
                {
                    ize = new IzPackException(exception.getMessage(), exception);
                }
                switch (ize.getPromptType())
                {
                    case ERROR:
                        prompt.message(ize);
                        break;

                    case WARNING:
                        AbstractUIHandler handler = new PromptUIHandler(prompt);
                        if (handler.askWarningQuestion(null,
                                AbstractPrompt.getThrowableMessage(ize) + "\n" + messages.get("installer.continueQuestion"),
                                AbstractUIHandler.CHOICES_YES_NO,
                                AbstractUIHandler.ANSWER_NO)
                                == AbstractUIHandler.ANSWER_YES)
                        {
                            return;
                        }
                        break;

                    default:
                        break;
                }
            }

            housekeeper.shutDown(4);
        }
        finally
        {
            cleanup();
            logEpilog();
            IOUtils.closeQuietly(objIn);
        }
    }
```

```diff
@@ -72,6 +72,7 @@
 import java.net.URL;
+import java.nio.file.Path;
 import java.util.ArrayList;
@@ -82,6 +83,7 @@
 import java.util.logging.Logger;
+import java.util.regex.Pattern;
 
@@ -93,8 +95,22 @@
  */
-public abstract class UnpackerBase implements IUnpacker
-{
+public abstract class UnpackerBase implements IUnpacker {
+    /**
+     * A compiled regular expression pattern used to match reserved device names in the Windows
+     * operating system. These names represent system-reserved keywords which cannot be used
+     * as file or directory names in Windows environments. The pattern is case-insensitive and
+     * matches the following names:
+     * <p>
+     * - CON
+     * - PRN
+     * - AUX
+     * - NUL
+     * - COM followed by digits 1 through 9 (e.g., COM1, COM2, etc.)
+     * - LPT followed by digits 1 through 9 (e.g., LPT1, LPT2, etc.)
+     */
+    private static final Pattern WINDOWS_RESERVED_DEVICE_NAMES_PATTERN = Pattern.compile("(?i)CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]");
+
     /**
@@ -185,8 +201,7 @@ public abstract class UnpackerBase implements IUnpacker
      */
-    private enum State
-    {
+    private enum State {
         READY, UNPACKING, INTERRUPT, INTERRUPTED
@@ -222,8 +237,7 @@ private enum State
                         Housekeeper housekeeper, InstallerListeners listeners, Prompt prompt,
-                        PlatformModelMatcher matcher)
-    {
+                        PlatformModelMatcher matcher) {
         this.installData = installData;
@@ -236,11 +250,9 @@ public UnpackerBase(InstallData installData, PackResources resources, RulesEngin
         this.messages = installData.getMessages();
-        cancellable = new Cancellable()
-        {
+        cancellable = new Cancellable() {
             @Override
-            public boolean isCancelled()
-            {
+            public boolean isCancelled() {
                 return isInterrupted();
@@ -252,8 +264,7 @@ public boolean isCancelled()
     @Override
-    public void setProgressListener(ProgressListener listener)
-    {
+    public void setProgressListener(ProgressListener listener) {
         this.listener = listener;
@@ -261,14 +272,12 @@ public void setProgressListener(ProgressListener listener)
     @Override
-    public void run()
-    {
+    public void run() {
         resetLogging();
 
-    private void logIntro()
-    {
+    private void logIntro() {
         final String startMessage = messages.get("installer.started");
@@ -276,36 +285,30 @@ private void logIntro()
         URL url = getClass().getClassLoader().getResource("META-INF/MANIFEST.MF");
... (truncated)
```

## 28. GHSA-f63g-88cj-hjf9:java.lang.security.audit.object-deserialization.object-deserialization:izpack-installer/src/main/java/com/izforge/izpack/installer/unpacker/UnpackerBase.java:1206

- tags: off-CWE, method-only
- advisory: IzPack has Path Traversal in UnpackerBase that allows writing files outside the installation directory via malicious pack entries
- repo: izpack/izpack  commit: 4233ba38d0f1825f9cf3e0204e5261a5498e29d8
- entry CWE: ['CWE-22']  finding CWEs: ['CWE-502']
- rule: object-deserialization
- finding: izpack-installer/src/main/java/com/izforge/izpack/installer/unpacker/UnpackerBase.java:1206 method writeInstallationInformation
- message: Found object deserialization using ObjectInputStream. Deserializing entire Java objects is dangerous because malicious actors can create Java object streams with unintended consequences. Ensure that the objects being deserialized are not user-controlled. If this must be done, consider using HMACs to sign the data stream to make sure it is not tampered with, or consider only transmitting object fields and populating a new object.

```java
public abstract class UnpackerBase implements IUnpacker
{

    protected void writeInstallationInformation() throws IOException
    {
        if (!installData.getInfo().isWriteInstallationInformation())
        {
            logger.fine("Skip writing installation information");
            return;
        }
        logger.fine("Writing installation information");
        String installDir = installData.getInstallPath();

        List<Pack> installedPacks = new ArrayList<Pack>(selectedPacks);

        File installationInfo = new File(installDir + File.separator + InstallData.INSTALLATION_INFORMATION);
        if (!installationInfo.exists())
        {
            logger.fine("Creating info file " + installationInfo.getAbsolutePath());
            File dir = new File(installData.getInstallPath());
            if (!dir.exists())
            {
                // if no packs have been installed, then the installation directory won't exist
                if (!dir.mkdirs())
                {
                    throw new InstallerException("Failed to create directory: " + dir);
                }
            }
            if (!installationInfo.createNewFile())
            {
                throw new InstallerException("Failed to create file: " + installationInfo);
            }
        } else
        {
            logger.fine("Previous installation information found");
            // read in old information and update
            FileInputStream fin = new FileInputStream(installationInfo);
            ObjectInputStream oin = new ObjectInputStream(fin);

            List<Pack> packs;
            try
            {
                //noinspection unchecked
                packs = (List<Pack>) oin.readObject();
            }
            catch (Exception exception)
            {
                throw new InstallerException("Failed to read previous installation information", exception);
            }
            finally
            {
                IOUtils.closeQuietly(oin);
                IOUtils.closeQuietly(fin);
            }
            installedPacks.addAll(packs);
        }

        FileOutputStream fout = new FileOutputStream(installationInfo);
        ObjectOutputStream oout = new ObjectOutputStream(fout);
        oout.writeObject(installedPacks);
        oout.writeObject(variables.getProperties());

        logger.fine("Writing installation information finished");
        IOUtils.closeQuietly(oout);
        IOUtils.closeQuietly(fout);

        uninstallData.addFile(installationInfo.getAbsolutePath(), true);
    }
```

```diff
@@ -72,6 +72,7 @@
 import java.net.URL;
+import java.nio.file.Path;
 import java.util.ArrayList;
@@ -82,6 +83,7 @@
 import java.util.logging.Logger;
+import java.util.regex.Pattern;
 
@@ -93,8 +95,22 @@
  */
-public abstract class UnpackerBase implements IUnpacker
-{
+public abstract class UnpackerBase implements IUnpacker {
+    /**
+     * A compiled regular expression pattern used to match reserved device names in the Windows
+     * operating system. These names represent system-reserved keywords which cannot be used
+     * as file or directory names in Windows environments. The pattern is case-insensitive and
+     * matches the following names:
+     * <p>
+     * - CON
+     * - PRN
+     * - AUX
+     * - NUL
+     * - COM followed by digits 1 through 9 (e.g., COM1, COM2, etc.)
+     * - LPT followed by digits 1 through 9 (e.g., LPT1, LPT2, etc.)
+     */
+    private static final Pattern WINDOWS_RESERVED_DEVICE_NAMES_PATTERN = Pattern.compile("(?i)CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]");
+
     /**
@@ -185,8 +201,7 @@ public abstract class UnpackerBase implements IUnpacker
      */
-    private enum State
-    {
+    private enum State {
         READY, UNPACKING, INTERRUPT, INTERRUPTED
@@ -222,8 +237,7 @@ private enum State
                         Housekeeper housekeeper, InstallerListeners listeners, Prompt prompt,
-                        PlatformModelMatcher matcher)
-    {
+                        PlatformModelMatcher matcher) {
         this.installData = installData;
@@ -236,11 +250,9 @@ public UnpackerBase(InstallData installData, PackResources resources, RulesEngin
         this.messages = installData.getMessages();
-        cancellable = new Cancellable()
-        {
+        cancellable = new Cancellable() {
             @Override
-            public boolean isCancelled()
-            {
+            public boolean isCancelled() {
                 return isInterrupted();
@@ -252,8 +264,7 @@ public boolean isCancelled()
     @Override
-    public void setProgressListener(ProgressListener listener)
-    {
+    public void setProgressListener(ProgressListener listener) {
         this.listener = listener;
@@ -261,14 +272,12 @@ public void setProgressListener(ProgressListener listener)
     @Override
-    public void run()
-    {
+    public void run() {
         resetLogging();
 
-    private void logIntro()
-    {
+    private void logIntro() {
         final String startMessage = messages.get("installer.started");
@@ -276,36 +285,30 @@ private void logIntro()
         URL url = getClass().getClassLoader().getResource("META-INF/MANIFEST.MF");
... (truncated)
```

## 29. GHSA-f729-58x4-gqgf:java.lang.security.httpservlet-path-traversal.httpservlet-path-traversal:bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:140

- tags: method-only, on-CWE-sample
- advisory: CometVisu Backend for openHAB affected by RCE through path traversal
- repo: openhab/openhab-webui  commit: 630e8525835c698cf58856aa43782d92b18087f2
- entry CWE: ['CWE-22']  finding CWEs: ['CWE-22']
- rule: httpservlet-path-traversal
- finding: bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:140 method doGet
- message: Detected a potential path traversal. A malicious actor could control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables in file paths are sanitized. You may also consider using a utility method such as org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path.

```java
public class CometVisuServlet extends HttpServlet {

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        File requestedFile = getRequestedFile(req);

        String path = req.getPathInfo();
        if (path == null) {
            path = "/index.html";
        }
        Matcher matcher = sitemapPattern.matcher(path);
        if (matcher.find()) {
            // add headers for cometvisu clients autoconfiguration
            resp.setHeader("X-CometVisu-Backend-Name", "openhab");

            // serve autogenerated config from openhab sitemap if no real config file exists
            if (!requestedFile.exists()) {
                Sitemap sitemap = getSitemap(matcher.group(2));
                if (sitemap != null) {
                    logger.debug("reading sitemap '{}'", sitemap);
                    VisuConfig config = new VisuConfig(sitemap, cometVisuApp);

                    resp.setContentType(MediaType.APPLICATION_XML);
                    resp.getWriter().write(config.getConfigXml(req));
                    resp.flushBuffer();

                    return;
                } else {
                    logger.debug("Config file not found. Neither as normal config ('{}') nor as sitemap ('{}.sitemap')",
                            requestedFile, matcher.group(2));
                    resp.sendError(HttpServletResponse.SC_NOT_FOUND);
                    return;
                }
            }
        }
        if (requestedFile.getName().equalsIgnoreCase("hidden.php")) {
            // do not deliver the hidden php
            resp.sendError(HttpServletResponse.SC_FORBIDDEN);
        } else if (path.endsWith(rssLogPath)) {
            processRssLogRequest(requestedFile, req, resp);
        } else {
            processStaticRequest(requestedFile, req, resp, true);
        }
    }
```

```diff
@@ -20,7 +20,6 @@
 import java.io.RandomAccessFile;
-import java.io.UnsupportedEncodingException;
 import java.net.URLDecoder;
@@ -45,6 +44,7 @@
 
+import org.eclipse.jdt.annotation.NonNullByDefault;
 import org.eclipse.jdt.annotation.Nullable;
@@ -72,6 +72,7 @@
  */
+@NonNullByDefault
 public class CometVisuServlet extends HttpServlet {
@@ -138,6 +139,10 @@ public final void init(@Nullable ServletConfig config) throws ServletException {
         File requestedFile = getRequestedFile(req);
+        if (requestedFile == null) {
+            resp.sendError(HttpServletResponse.SC_NOT_FOUND);
+            return;
+        }
 
@@ -168,6 +173,10 @@ protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Se
         }
+        if (requestedFile.getName().equalsIgnoreCase("version")) {
+            // tell client that its been served by openhab
+            resp.setHeader("X-CometVisu-Backend-Name", "openhab");
+        }
         if (requestedFile.getName().equalsIgnoreCase("hidden.php")) {
@@ -178,7 +187,7 @@ protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Se
 
-    protected File getRequestedFile(HttpServletRequest req) throws UnsupportedEncodingException {
+    protected @Nullable File getRequestedFile(HttpServletRequest req) throws IOException {
         String requestedFile = req.getPathInfo();
@@ -188,12 +197,18 @@ protected File getRequestedFile(HttpServletRequest req) throws UnsupportedEncodi
             file = new File(userFileFolder, URLDecoder.decode(requestedFile, StandardCharsets.UTF_8));
+            if (!file.getCanonicalPath().startsWith(userFileFolder.getCanonicalPath() + File.separator)) {
+                return null;
+            }
         }
                     : rootFolder;
+            if (!file.getCanonicalPath().startsWith(rootFolder.getCanonicalPath() + File.separator)) {
+                return null;
+            }
         }
```

## 30. GHSA-f729-58x4-gqgf:java.lang.security.httpservlet-path-traversal.httpservlet-path-traversal:bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:190

- tags: method-only, on-CWE-sample
- advisory: CometVisu Backend for openHAB affected by RCE through path traversal
- repo: openhab/openhab-webui  commit: 630e8525835c698cf58856aa43782d92b18087f2
- entry CWE: ['CWE-22']  finding CWEs: ['CWE-22']
- rule: httpservlet-path-traversal
- finding: bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:190 method getRequestedFile
- message: Detected a potential path traversal. A malicious actor could control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables in file paths are sanitized. You may also consider using a utility method such as org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path.

```java
public class CometVisuServlet extends HttpServlet {

    protected File getRequestedFile(HttpServletRequest req) throws UnsupportedEncodingException {
        String requestedFile = req.getPathInfo();
        File file = null;

        // check services folder if a file exists there
        if (requestedFile != null) {
            if (requestedFile.endsWith("/")) {
                requestedFile = requestedFile.substring(0, requestedFile.length() - 1);
            }
            file = new File(userFileFolder, URLDecoder.decode(requestedFile, StandardCharsets.UTF_8));
        }
        // serve the file from the cometvisu src directory
        if (file == null || !file.exists() || file.isDirectory()) {
            file = requestedFile != null
                    ? new File(rootFolder, URLDecoder.decode(requestedFile, StandardCharsets.UTF_8))
                    : rootFolder;
        }
        if (file.isDirectory()) {
            // search for an index file
            FilenameFilter filter = (dir, name) -> name != null && name.startsWith("index.")
                    && (name.endsWith(".php") || name.endsWith(".html"));
            for (String dirFile : file.list(filter)) {
                // take the first one found
                file = new File(file, dirFile);
                break;
            }
        }
        return file;
    }
```

```diff
@@ -20,7 +20,6 @@
 import java.io.RandomAccessFile;
-import java.io.UnsupportedEncodingException;
 import java.net.URLDecoder;
@@ -45,6 +44,7 @@
 
+import org.eclipse.jdt.annotation.NonNullByDefault;
 import org.eclipse.jdt.annotation.Nullable;
@@ -72,6 +72,7 @@
  */
+@NonNullByDefault
 public class CometVisuServlet extends HttpServlet {
@@ -138,6 +139,10 @@ public final void init(@Nullable ServletConfig config) throws ServletException {
         File requestedFile = getRequestedFile(req);
+        if (requestedFile == null) {
+            resp.sendError(HttpServletResponse.SC_NOT_FOUND);
+            return;
+        }
 
@@ -168,6 +173,10 @@ protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Se
         }
+        if (requestedFile.getName().equalsIgnoreCase("version")) {
+            // tell client that its been served by openhab
+            resp.setHeader("X-CometVisu-Backend-Name", "openhab");
+        }
         if (requestedFile.getName().equalsIgnoreCase("hidden.php")) {
@@ -178,7 +187,7 @@ protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Se
 
-    protected File getRequestedFile(HttpServletRequest req) throws UnsupportedEncodingException {
+    protected @Nullable File getRequestedFile(HttpServletRequest req) throws IOException {
         String requestedFile = req.getPathInfo();
@@ -188,12 +197,18 @@ protected File getRequestedFile(HttpServletRequest req) throws UnsupportedEncodi
             file = new File(userFileFolder, URLDecoder.decode(requestedFile, StandardCharsets.UTF_8));
+            if (!file.getCanonicalPath().startsWith(userFileFolder.getCanonicalPath() + File.separator)) {
+                return null;
+            }
         }
                     : rootFolder;
+            if (!file.getCanonicalPath().startsWith(rootFolder.getCanonicalPath() + File.separator)) {
+                return null;
+            }
         }
```

## 31. GHSA-f729-58x4-gqgf:java.lang.security.httpservlet-path-traversal.httpservlet-path-traversal:bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:194

- tags: method-only
- advisory: CometVisu Backend for openHAB affected by RCE through path traversal
- repo: openhab/openhab-webui  commit: 630e8525835c698cf58856aa43782d92b18087f2
- entry CWE: ['CWE-22']  finding CWEs: ['CWE-22']
- rule: httpservlet-path-traversal
- finding: bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:194 method getRequestedFile
- message: Detected a potential path traversal. A malicious actor could control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables in file paths are sanitized. You may also consider using a utility method such as org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path.

```java
public class CometVisuServlet extends HttpServlet {

    protected File getRequestedFile(HttpServletRequest req) throws UnsupportedEncodingException {
        String requestedFile = req.getPathInfo();
        File file = null;

        // check services folder if a file exists there
        if (requestedFile != null) {
            if (requestedFile.endsWith("/")) {
                requestedFile = requestedFile.substring(0, requestedFile.length() - 1);
            }
            file = new File(userFileFolder, URLDecoder.decode(requestedFile, StandardCharsets.UTF_8));
        }
        // serve the file from the cometvisu src directory
        if (file == null || !file.exists() || file.isDirectory()) {
            file = requestedFile != null
                    ? new File(rootFolder, URLDecoder.decode(requestedFile, StandardCharsets.UTF_8))
                    : rootFolder;
        }
        if (file.isDirectory()) {
            // search for an index file
            FilenameFilter filter = (dir, name) -> name != null && name.startsWith("index.")
                    && (name.endsWith(".php") || name.endsWith(".html"));
            for (String dirFile : file.list(filter)) {
                // take the first one found
                file = new File(file, dirFile);
                break;
            }
        }
        return file;
    }
```

```diff
@@ -20,7 +20,6 @@
 import java.io.RandomAccessFile;
-import java.io.UnsupportedEncodingException;
 import java.net.URLDecoder;
@@ -45,6 +44,7 @@
 
+import org.eclipse.jdt.annotation.NonNullByDefault;
 import org.eclipse.jdt.annotation.Nullable;
@@ -72,6 +72,7 @@
  */
+@NonNullByDefault
 public class CometVisuServlet extends HttpServlet {
@@ -138,6 +139,10 @@ public final void init(@Nullable ServletConfig config) throws ServletException {
         File requestedFile = getRequestedFile(req);
+        if (requestedFile == null) {
+            resp.sendError(HttpServletResponse.SC_NOT_FOUND);
+            return;
+        }
 
@@ -168,6 +173,10 @@ protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Se
         }
+        if (requestedFile.getName().equalsIgnoreCase("version")) {
+            // tell client that its been served by openhab
+            resp.setHeader("X-CometVisu-Backend-Name", "openhab");
+        }
         if (requestedFile.getName().equalsIgnoreCase("hidden.php")) {
@@ -178,7 +187,7 @@ protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Se
 
-    protected File getRequestedFile(HttpServletRequest req) throws UnsupportedEncodingException {
+    protected @Nullable File getRequestedFile(HttpServletRequest req) throws IOException {
         String requestedFile = req.getPathInfo();
@@ -188,12 +197,18 @@ protected File getRequestedFile(HttpServletRequest req) throws UnsupportedEncodi
             file = new File(userFileFolder, URLDecoder.decode(requestedFile, StandardCharsets.UTF_8));
+            if (!file.getCanonicalPath().startsWith(userFileFolder.getCanonicalPath() + File.separator)) {
+                return null;
+            }
         }
                     : rootFolder;
+            if (!file.getCanonicalPath().startsWith(rootFolder.getCanonicalPath() + File.separator)) {
+                return null;
+            }
         }
```

## 32. GHSA-f729-58x4-gqgf:java.lang.security.httpservlet-path-traversal.httpservlet-path-traversal:bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:204

- tags: method-only
- advisory: CometVisu Backend for openHAB affected by RCE through path traversal
- repo: openhab/openhab-webui  commit: 630e8525835c698cf58856aa43782d92b18087f2
- entry CWE: ['CWE-22']  finding CWEs: ['CWE-22']
- rule: httpservlet-path-traversal
- finding: bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:204 method getRequestedFile
- message: Detected a potential path traversal. A malicious actor could control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables in file paths are sanitized. You may also consider using a utility method such as org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path.

```java
public class CometVisuServlet extends HttpServlet {

    protected File getRequestedFile(HttpServletRequest req) throws UnsupportedEncodingException {
        String requestedFile = req.getPathInfo();
        File file = null;

        // check services folder if a file exists there
        if (requestedFile != null) {
            if (requestedFile.endsWith("/")) {
                requestedFile = requestedFile.substring(0, requestedFile.length() - 1);
            }
            file = new File(userFileFolder, URLDecoder.decode(requestedFile, StandardCharsets.UTF_8));
        }
        // serve the file from the cometvisu src directory
        if (file == null || !file.exists() || file.isDirectory()) {
            file = requestedFile != null
                    ? new File(rootFolder, URLDecoder.decode(requestedFile, StandardCharsets.UTF_8))
                    : rootFolder;
        }
        if (file.isDirectory()) {
            // search for an index file
            FilenameFilter filter = (dir, name) -> name != null && name.startsWith("index.")
                    && (name.endsWith(".php") || name.endsWith(".html"));
            for (String dirFile : file.list(filter)) {
                // take the first one found
                file = new File(file, dirFile);
                break;
            }
        }
        return file;
    }
```

```diff
@@ -20,7 +20,6 @@
 import java.io.RandomAccessFile;
-import java.io.UnsupportedEncodingException;
 import java.net.URLDecoder;
@@ -45,6 +44,7 @@
 
+import org.eclipse.jdt.annotation.NonNullByDefault;
 import org.eclipse.jdt.annotation.Nullable;
@@ -72,6 +72,7 @@
  */
+@NonNullByDefault
 public class CometVisuServlet extends HttpServlet {
@@ -138,6 +139,10 @@ public final void init(@Nullable ServletConfig config) throws ServletException {
         File requestedFile = getRequestedFile(req);
+        if (requestedFile == null) {
+            resp.sendError(HttpServletResponse.SC_NOT_FOUND);
+            return;
+        }
 
@@ -168,6 +173,10 @@ protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Se
         }
+        if (requestedFile.getName().equalsIgnoreCase("version")) {
+            // tell client that its been served by openhab
+            resp.setHeader("X-CometVisu-Backend-Name", "openhab");
+        }
         if (requestedFile.getName().equalsIgnoreCase("hidden.php")) {
@@ -178,7 +187,7 @@ protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Se
 
-    protected File getRequestedFile(HttpServletRequest req) throws UnsupportedEncodingException {
+    protected @Nullable File getRequestedFile(HttpServletRequest req) throws IOException {
         String requestedFile = req.getPathInfo();
@@ -188,12 +197,18 @@ protected File getRequestedFile(HttpServletRequest req) throws UnsupportedEncodi
             file = new File(userFileFolder, URLDecoder.decode(requestedFile, StandardCharsets.UTF_8));
+            if (!file.getCanonicalPath().startsWith(userFileFolder.getCanonicalPath() + File.separator)) {
+                return null;
+            }
         }
                     : rootFolder;
+            if (!file.getCanonicalPath().startsWith(rootFolder.getCanonicalPath() + File.separator)) {
+                return null;
+            }
         }
```

## 33. GHSA-fmj2-7wx8-qj4v:java.lang.security.audit.xxe.transformerfactory-dtds-not-disabled.transformerfactory-dtds-not-disabled:src/main/java/org/apache/xmlgraphics/xmp/XMPParser.java:57

- tags: off-CWE, method-only
- advisory: Server-side request forgery (SSRF) in Apache XmlGraphics Commons
- repo: apache/xmlgraphics-commons  commit: 57393912eb87b994c7fed39ddf30fb778a275183
- entry CWE: ['CWE-918']  finding CWEs: ['CWE-611']
- rule: transformerfactory-dtds-not-disabled
- finding: src/main/java/org/apache/xmlgraphics/xmp/XMPParser.java:57 method parseXMP
- message: DOCTYPE declarations are enabled for this TransformerFactory. This is vulnerable to XML external entity attacks. Disable this by setting the attributes "accessExternalDTD" and "accessExternalStylesheet" to "".

```java
public final class XMPParser {

    public static Metadata parseXMP(Source src) throws TransformerException {
        TransformerFactory tFactory = TransformerFactory.newInstance();
        Transformer transformer = tFactory.newTransformer();
        XMPHandler handler = createXMPHandler();
        SAXResult res = new SAXResult(handler);
        transformer.transform(src, res);
        return handler.getMetadata();
    }
```

```diff
@@ -21,6 +21,7 @@
 
+import javax.xml.XMLConstants;
 import javax.xml.transform.Source;
@@ -54,6 +55,8 @@ public static Metadata parseXMP(URL url) throws TransformerException {
         TransformerFactory tFactory = TransformerFactory.newInstance();
+        tFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
+        tFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
         Transformer transformer = tFactory.newTransformer();
```

## 34. GHSA-g4r8-28fp-f255:java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing.documentbuilderfactory-disallow-doctype-decl-missing:src/main/java/de/timroes/axmlrpc/ResponseParser.java:51

- tags: method-only, on-CWE-sample
- advisory: aXMLRPC XML External Entity vulnerability
- repo: gturri/aXMLRPC  commit: 456752ebc1ef4c0db980cb5b01a0b3cd0a9e0bae
- entry CWE: ['CWE-611']  finding CWEs: ['CWE-611']
- rule: documentbuilderfactory-disallow-doctype-decl-missing
- finding: src/main/java/de/timroes/axmlrpc/ResponseParser.java:51 method parse
- message: DOCTYPE declarations are enabled for this DocumentBuilderFactory. This is vulnerable to XML external entity attacks. Disable this by setting the feature "http://apache.org/xml/features/disallow-doctype-decl" to true. Alternatively, allow DOCTYPE declarations and only prohibit external entities declarations. This can be done by setting the features "http://xml.org/sax/features/external-general-entities" and "http://xml.org/sax/features/external-parameter-entities" to false.

```java
public class ResponseParser {

	public Object parse(SerializerHandler serializerHandler, InputStream response, boolean debugMode) throws XMLRPCException {

		try {

			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setNamespaceAware(true);
			DocumentBuilder builder = factory.newDocumentBuilder();
			Document dom = builder.parse(response);
			if (debugMode ){
				printDocument(dom, System.out);
			}
			Element e = dom.getDocumentElement();


			// Check for root tag
			if(!e.getNodeName().equals(XMLRPCClient.METHOD_RESPONSE)) {
				throw new XMLRPCException("MethodResponse root tag is missing.");
			}

			e = XMLUtil.getOnlyChildElement(e.getChildNodes());

			if(e.getNodeName().equals(XMLRPCClient.PARAMS)) {

				e = XMLUtil.getOnlyChildElement(e.getChildNodes());

				if(!e.getNodeName().equals(XMLRPCClient.PARAM)) {
					throw new XMLRPCException("The params tag must contain a param tag.");
				}

				return getReturnValueFromElement(serializerHandler, e);

			} else if(e.getNodeName().equals(XMLRPCClient.FAULT)) {

				@SuppressWarnings("unchecked")
				Map<String,Object> o = (Map<String,Object>)getReturnValueFromElement(serializerHandler, e);

				throw new XMLRPCServerException((String)o.get(FAULT_STRING), (Integer)o.get(FAULT_CODE));

			}

			throw new XMLRPCException("The methodResponse tag must contain a fault or params tag.");

		} catch(XMLRPCServerException e) {
			throw e;
		} catch (Exception ex) {
			throw new XMLRPCException("Error getting result from server.", ex);
		}

	}
```

```diff
@@ -10,6 +10,7 @@
 import javax.xml.parsers.DocumentBuilderFactory;
+import javax.xml.parsers.ParserConfigurationException;
 import javax.xml.transform.OutputKeys;
@@ -45,9 +46,17 @@ public class ResponseParser {
 		try {
-
 			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
+
+			// Ensure the xml parser won't allow exploitation of the vuln CWE-611
+			// (described on https://cwe.mitre.org/data/definitions/611.html )
+			factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
+			factory.setExpandEntityReferences(false);
 			factory.setNamespaceAware(true);
+			factory.setXIncludeAware(false);
+			factory.setExpandEntityReferences(false);
+			// End of the configuration of the parser for CWE-611
+
 			DocumentBuilder builder = factory.newDocumentBuilder();
```

## 35. GHSA-g5mj-c26g-vmpm:java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing.documentbuilderfactory-disallow-doctype-decl-missing:src/main/java/com/smartbear/jenkins/plugins/testcomplete/parser/LogNodeUtils.java:172

- tags: method-only, on-CWE-sample
- advisory: XML Entity Expansion in Jenkins TestComplete support Plugin
- repo: jenkinsci/testcomplete-plugin  commit: 971003ea578a090ed9a5b9487acb9d2aa93645d3
- entry CWE: ['CWE-611']  finding CWEs: ['CWE-611']
- rule: documentbuilderfactory-disallow-doctype-decl-missing
- finding: src/main/java/com/smartbear/jenkins/plugins/testcomplete/parser/LogNodeUtils.java:172 method getRootDocumentNodeFromArchive
- message: DOCTYPE declarations are enabled for this DocumentBuilderFactory. This is vulnerable to XML external entity attacks. Disable this by setting the feature "http://apache.org/xml/features/disallow-doctype-decl" to true. Alternatively, allow DOCTYPE declarations and only prohibit external entities declarations. This can be done by setting the features "http://xml.org/sax/features/external-general-entities" and "http://xml.org/sax/features/external-parameter-entities" to false.

```java
class LogNodeUtils {

    static public Node getRootDocumentNodeFromArchive(ZipFile archive, String name) {
        if (name == null) {
            return null;
        }

        ZipEntry rootLogDataEntry = archive.getEntry(name);
        if (rootLogDataEntry == null) {
            return null;
        }

        InputStream logDataStream = null;
        try {
            logDataStream = archive.getInputStream(rootLogDataEntry);
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();

            Document document = builder.parse(logDataStream);

            Element element = document.getDocumentElement();
            if (!"1".equals(element.getAttribute("version"))) {
                return null;
            }

            NodeList list = element.getChildNodes();

            for (int i = 0; i < list.getLength(); i++) {
                Node item = list.item(i);
                NamedNodeMap attributes = item.getAttributes();
                if (attributes != null && attributes.getNamedItem("name") != null) {
                    String nodeName = attributes.getNamedItem("name").getNodeValue();
                    if ("root".equals(nodeName)) {
                        return item;
                    }
                }
            }
        } catch (IOException | ParserConfigurationException | SAXException e) {
            // Do nothing
        } finally {
            if (logDataStream != null) {
                try {
                    logDataStream.close();
                } catch (IOException e) {
                    // Do nothing
                }
            }
        }

        return null;
    }
```

```diff
@@ -37,6 +37,7 @@
 import java.util.zip.ZipFile;
+import javax.xml.XMLConstants;
 
@@ -155,6 +156,30 @@ static public Node findRootOwnerNode(NodeList nodes) {
 
+    static private final String DISALLOW_DOCTYPE_DECL = 
+        "http://apache.org/xml/features/disallow-doctype-decl";
+    
+    static private final String EXTERNAL_GENERAL_ENTITIES = 
+        "http://xml.org/sax/features/external-general-entities";
+
+    static private final String EXTERNAL_PARAMETER_ENTITIES = 
+        "http://xml.org/sax/features/external-parameter-entities";
+
+    static private final String LOAD_EXTERNAL_DTD = 
+        "http://apache.org/xml/features/nonvalidating/load-external-dtd";
+
+    // This is added to prevent XXE attack on xml parser
+    static private void secureDocumentBuilderFactory(DocumentBuilderFactory factory) 
+        throws ParserConfigurationException {
+        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
+        factory.setFeature(EXTERNAL_GENERAL_ENTITIES , false);
+        factory.setFeature(EXTERNAL_PARAMETER_ENTITIES, false);
+        factory.setFeature(LOAD_EXTERNAL_DTD, false);
+        factory.setXIncludeAware(false);
+        factory.setExpandEntityReferences(false);
+    }
+
+
     static public Node getRootDocumentNodeFromArchive(ZipFile archive, String name) {
@@ -169,6 +194,7 @@ static public Node getRootDocumentNodeFromArchive(ZipFile archive, String name)
             DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
+            secureDocumentBuilderFactory(factory);
             DocumentBuilder builder = factory.newDocumentBuilder();
```

## 36. GHSA-g43x-pcc9-f472:java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing.documentbuilderfactory-disallow-doctype-decl-missing:src/main/java/com/compuware/jenkins/common/utils/CLIVersionUtils.java:192

- tags: method-only
- advisory: Jenkins Compuware Common Configuration Plugin vulnerable to Improper Restriction of XML External Entity Reference
- repo: jenkinsci/compuware-common-configuration-plugin  commit: 351a46798cdc10479cb6966f05a51bc2174806a0
- entry CWE: ['CWE-611']  finding CWEs: ['CWE-611']
- rule: documentbuilderfactory-disallow-doctype-decl-missing
- finding: src/main/java/com/compuware/jenkins/common/utils/CLIVersionUtils.java:192 method parseXml
- message: DOCTYPE declarations are enabled for this DocumentBuilderFactory. This is vulnerable to XML external entity attacks. Disable this by setting the feature "http://apache.org/xml/features/disallow-doctype-decl" to true. Alternatively, allow DOCTYPE declarations and only prohibit external entities declarations. This can be done by setting the features "http://xml.org/sax/features/external-general-entities" and "http://xml.org/sax/features/external-parameter-entities" to false.

```java
public class CLIVersionUtils
{

	private static String parseXml(InputStream versionfile) throws IOException
	{
		String version = ""; //$NON-NLS-1$
		
		try
		{
		    DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
		    DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
		    Document document = dBuilder.parse(versionfile);
		    
			version = document.getDocumentElement().getAttribute("version"); //$NON-NLS-1$
		}
		catch (ParserConfigurationException | SAXException e)
		{
			throw new AbortException(Messages.cliParseXmlError());
		}
		
		return version;
	}
```

```diff
@@ -189,6 +189,8 @@ private static String parseXml(InputStream versionfile) throws IOException
 		    DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
+		    dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); 
+		    dbFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
 		    DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
```

## 37. GHSA-h7qf-qmf3-85qg:java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing.documentbuilderfactory-disallow-doctype-decl-missing:plugins/junit-xml-plugin/src/main/java/io/qameta/allure/junitxml/JunitXmlPlugin.java:136

- tags: method-only
- advisory: Allure Report allows Improper XXE Restriction via DocumentBuilderFactory
- repo: allure-framework/allure2  commit: cbcb33719851ff70adce85d38e15d20fc58d4eb7
- entry CWE: ['CWE-611']  finding CWEs: ['CWE-611']
- rule: documentbuilderfactory-disallow-doctype-decl-missing
- finding: plugins/junit-xml-plugin/src/main/java/io/qameta/allure/junitxml/JunitXmlPlugin.java:136 method parseRootElement
- message: DOCTYPE declarations are enabled for this DocumentBuilderFactory. This is vulnerable to XML external entity attacks. Disable this by setting the feature "http://apache.org/xml/features/disallow-doctype-decl" to true. Alternatively, allow DOCTYPE declarations and only prohibit external entities declarations. This can be done by setting the features "http://xml.org/sax/features/external-general-entities" and "http://xml.org/sax/features/external-parameter-entities" to false.

```java
public class JunitXmlPlugin implements Reader {

    private void parseRootElement(final Path resultsDirectory, final Path parsedFile,
                                  final RandomUidContext context, final ResultsVisitor visitor) {
        try {
            LOGGER.debug("Parsing file {}", parsedFile);
            final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            final DocumentBuilder builder = factory.newDocumentBuilder();

            final XmlElement rootElement = new XmlElement(builder.parse(parsedFile.toFile()).getDocumentElement());
            final String elementName = rootElement.getName();

            if (TEST_SUITE_ELEMENT_NAME.equals(elementName)) {
                parseTestSuite(rootElement, parsedFile, context, visitor, resultsDirectory);
                return;
            }
            if (TEST_SUITES_ELEMENT_NAME.equals(elementName)) {
                rootElement.get(TEST_SUITE_ELEMENT_NAME)
                        .forEach(element -> parseTestSuite(element, parsedFile, context, visitor, resultsDirectory));
                return;
            }
            LOGGER.debug("File {} is not a valid JUnit xml. Unknown root element {}", parsedFile, elementName);
        } catch (SAXException | ParserConfigurationException | IOException e) {
            LOGGER.error("Could not parse file {}: {}", parsedFile, e);
        }
    }
```

```diff
@@ -30,6 +30,7 @@
 import io.qameta.allure.entity.Time;
+import io.qameta.allure.parser.ClasspathEntityResolver;
 import io.qameta.allure.parser.XmlElement;
@@ -133,7 +134,9 @@ private void parseRootElement(final Path resultsDirectory, final Path parsedFile
             final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
+            factory.setValidating(false);
             final DocumentBuilder builder = factory.newDocumentBuilder();
+            builder.setEntityResolver(new ClasspathEntityResolver());
 
```

## 38. GHSA-h7qf-qmf3-85qg:java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing.documentbuilderfactory-disallow-doctype-decl-missing:plugins/trx-plugin/src/main/java/io/qameta/allure/trx/TrxPlugin.java:109

- tags: method-only
- advisory: Allure Report allows Improper XXE Restriction via DocumentBuilderFactory
- repo: allure-framework/allure2  commit: cbcb33719851ff70adce85d38e15d20fc58d4eb7
- entry CWE: ['CWE-611']  finding CWEs: ['CWE-611']
- rule: documentbuilderfactory-disallow-doctype-decl-missing
- finding: plugins/trx-plugin/src/main/java/io/qameta/allure/trx/TrxPlugin.java:109 method parseTestRun
- message: DOCTYPE declarations are enabled for this DocumentBuilderFactory. This is vulnerable to XML external entity attacks. Disable this by setting the feature "http://apache.org/xml/features/disallow-doctype-decl" to true. Alternatively, allow DOCTYPE declarations and only prohibit external entities declarations. This can be done by setting the features "http://xml.org/sax/features/external-general-entities" and "http://xml.org/sax/features/external-parameter-entities" to false.

```java
public class TrxPlugin implements Reader {

    protected void parseTestRun(final Path parsedFile, final RandomUidContext context, final ResultsVisitor visitor) {
        try {
            LOGGER.debug("Parsing file {}", parsedFile);

            final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            final DocumentBuilder builder = factory.newDocumentBuilder();
            final Document document = builder.parse(parsedFile.toFile());
            final XmlElement testRunElement = new XmlElement(document.getDocumentElement());
            final String elementName = testRunElement.getName();
            if (!TEST_RUN_ELEMENT_NAME.equals(elementName)) {
                LOGGER.debug("{} is not a valid TRX file. Unknown root element {}", parsedFile, elementName);
                return;
            }
            final Map<String, UnitTest> tests = new HashMap<>();
            testRunElement.getFirst(TEST_DEFINITIONS_ELEMENT)
                    .ifPresent(testDefinitions -> {
                        testDefinitions.get(UNIT_TEST_ELEMENT).forEach(unitTestElement -> {
                            final UnitTest unitTest = parseUnitTest(unitTestElement);
                            tests.put(unitTest.getExecutionId(), unitTest);
                        });
                    });
            testRunElement.getFirst(RESULTS_ELEMENT_NAME)
                    .ifPresent(resultsElement -> parseResults(resultsElement, tests, context, visitor));
        } catch (SAXException | ParserConfigurationException | IOException e) {
            LOGGER.error("Could not parse file {}", parsedFile, e);
        }
    }
```

```diff
@@ -25,6 +25,7 @@
 import io.qameta.allure.entity.Time;
+import io.qameta.allure.parser.ClasspathEntityResolver;
 import io.qameta.allure.parser.XmlElement;
@@ -106,7 +107,9 @@ protected void parseTestRun(final Path parsedFile, final RandomUidContext contex
             final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
+            factory.setValidating(false);
             final DocumentBuilder builder = factory.newDocumentBuilder();
+            builder.setEntityResolver(new ClasspathEntityResolver());
             final Document document = builder.parse(parsedFile.toFile());
```

## 39. GHSA-h7qf-qmf3-85qg:java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing.documentbuilderfactory-disallow-doctype-decl-missing:plugins/xunit-xml-plugin/src/main/java/io/qameta/allure/xunitxml/XunitXmlPlugin.java:97

- tags: method-only, on-CWE-sample
- advisory: Allure Report allows Improper XXE Restriction via DocumentBuilderFactory
- repo: allure-framework/allure2  commit: cbcb33719851ff70adce85d38e15d20fc58d4eb7
- entry CWE: ['CWE-611']  finding CWEs: ['CWE-611']
- rule: documentbuilderfactory-disallow-doctype-decl-missing
- finding: plugins/xunit-xml-plugin/src/main/java/io/qameta/allure/xunitxml/XunitXmlPlugin.java:97 method parseAssemblies
- message: DOCTYPE declarations are enabled for this DocumentBuilderFactory. This is vulnerable to XML external entity attacks. Disable this by setting the feature "http://apache.org/xml/features/disallow-doctype-decl" to true. Alternatively, allow DOCTYPE declarations and only prohibit external entities declarations. This can be done by setting the features "http://xml.org/sax/features/external-general-entities" and "http://xml.org/sax/features/external-parameter-entities" to false.

```java
public class XunitXmlPlugin implements Reader {

    private void parseAssemblies(final Path parsedFile, final RandomUidContext context, final ResultsVisitor visitor) {
        try {
            LOGGER.debug("Parsing file {}", parsedFile);
            final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            final DocumentBuilder builder = factory.newDocumentBuilder();
            final Document document = builder.parse(parsedFile.toFile());
            final XmlElement assembliesElement = new XmlElement(document.getDocumentElement());
            final String elementName = assembliesElement.getName();
            if (!ASSEMBLIES_ELEMENT_NAME.equals(elementName)) {
                LOGGER.debug("{} is not a valid XUnit xml file. Unknown root element {}", parsedFile, elementName);
                return;
            }

            assembliesElement.get(ASSEMBLY_ELEMENT_NAME)
                    .forEach(element -> parseAssembly(element, context, visitor));
        } catch (SAXException | ParserConfigurationException | IOException e) {
            LOGGER.error("Could not parse file {}: {}", parsedFile, e);
        }
    }
```

```diff
@@ -23,6 +23,7 @@
 import io.qameta.allure.entity.Time;
+import io.qameta.allure.parser.ClasspathEntityResolver;
 import io.qameta.allure.parser.XmlElement;
@@ -94,7 +95,9 @@ private void parseAssemblies(final Path parsedFile, final RandomUidContext conte
             final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
+            factory.setValidating(false);
             final DocumentBuilder builder = factory.newDocumentBuilder();
+            builder.setEntityResolver(new ClasspathEntityResolver());
             final Document document = builder.parse(parsedFile.toFile());
```

## 40. GHSA-hg25-w3vg-7279:java.lang.security.audit.crypto.ssl.defaulthttpclient-is-deprecated.defaulthttpclient-is-deprecated:modules/jpawebapi/src/com/haulmont/addon/jpawebapi/api/controller/RestFileDownloadController.java:148

- tags: off-CWE, method-only
- advisory: XSS in the /download Endpoint of the JPA Web API
- repo: cuba-platform/jpawebapi  commit: 78b837d7e2b12d0df69cef1bc6042ebf3bdaf22c
- entry CWE: ['CWE-79']  finding CWEs: ['CWE-326']
- rule: defaulthttpclient-is-deprecated
- finding: modules/jpawebapi/src/com/haulmont/addon/jpawebapi/api/controller/RestFileDownloadController.java:148 method writeResponse
- message: DefaultHttpClient is deprecated. Further, it does not support connections using TLS1.2, which makes using DefaultHttpClient a security hazard. Use HttpClientBuilder instead.

```java
public class RestFileDownloadController {

    protected void writeResponse(HttpServletResponse response, UserSession userSession, FileDescriptor fd)
            throws IOException {

        if (fileDownloadContext == null) {
            fileDownloadContext = clientConfig.getFileDownloadContext();
        }

        InputStream is = null;
        ServletOutputStream os = response.getOutputStream();
        try {
            Object context = serverSelector.initContext();
            String selectedUrl = serverSelector.getUrl(context);
            if (selectedUrl == null) {
                log.debug("Unable to download file: no available server URLs");
                error(response);
            }
            while (selectedUrl != null) {
                String url = selectedUrl + fileDownloadContext
                        + "?s=" + userSession.getId()
                        + "&f=" + fd.getId().toString();

                HttpClient httpClient = new DefaultHttpClient();
                HttpGet httpGet = new HttpGet(url);

                try {
                    HttpResponse httpResponse = httpClient.execute(httpGet);
                    int httpStatus = httpResponse.getStatusLine().getStatusCode();
                    if (httpStatus == HttpStatus.SC_OK) {
                        HttpEntity httpEntity = httpResponse.getEntity();
                        if (httpEntity != null) {
                            is = httpEntity.getContent();
                            IOUtils.copy(is, os);
                            os.flush();
                            break;
                        } else {
                            log.debug("Unable to download file from " + url + "\nHttpEntity is null");
                            selectedUrl = failAndGetNextUrl(context, response);
                        }
                    } else {
                        log.debug("Unable to download file from " + url + "\n" + httpResponse.getStatusLine());
                        selectedUrl = failAndGetNextUrl(context, response);
                    }
                } catch (IOException ex) {
                    log.debug("Unable to download file from " + url + "\n" + ex);
                    selectedUrl = failAndGetNextUrl(context, response);
                } finally {
                    IOUtils.closeQuietly(is);
                    httpClient.getConnectionManager().shutdown();
                }
            }
        } finally {
            IOUtils.closeQuietly(os);
        }
    }
```

```diff
@@ -17,6 +17,7 @@
 
+import com.haulmont.addon.jpawebapi.api.config.JpaWebApiConfig;
 import com.haulmont.bali.util.URLEncodeUtils;
@@ -30,6 +31,7 @@
 import org.apache.commons.io.IOUtils;
+import org.apache.commons.lang3.BooleanUtils;
 import org.apache.commons.lang3.StringUtils;
@@ -52,6 +54,7 @@
 import java.io.InputStream;
+import java.util.List;
 import java.util.UUID;
@@ -76,6 +79,9 @@ public class RestFileDownloadController {
 
+    @Inject
+    protected JpaWebApiConfig jpaWebApiConfig;
+
     protected String fileDownloadContext;
@@ -113,6 +119,9 @@ public ModelAndView download(HttpServletRequest request, HttpServletResponse res
             boolean attach = Boolean.valueOf(request.getParameter("a"));
+
+            attach = resolveAttachmentValue(attach, fd);
+
             response.setHeader("Content-Disposition", (attach ? "attachment" : "inline")
@@ -179,6 +188,22 @@ protected void writeResponse(HttpServletResponse response, UserSession userSessi
 
+    protected boolean resolveAttachmentValue(Boolean attachmentRequestParameterValue, FileDescriptor fileDescriptor) {
+        if (BooleanUtils.isTrue(attachmentRequestParameterValue)) {
+            return true;
+        }
+
+        String extension = fileDescriptor.getExtension();
+        if (StringUtils.isEmpty(extension)) {
+            // No extension - just download
+            return true;
+        } else {
+            // Check if file is allowed to be opened inline
+            List<String> inlineEnabledFileExtensions = jpaWebApiConfig.getInlineEnabledFileExtensions();
+            return !inlineEnabledFileExtensions.contains(StringUtils.lowerCase(extension));
+        }
+    }
+
     @Nullable
```

## 41. GHSA-j7jm-8gf5-frcm:java.lang.security.audit.object-deserialization.object-deserialization:ngrinder-core/src/main/java/net/grinder/communication/Connector.java:199

- tags: method-only, on-CWE-sample
- advisory: nGrinder vulnerable to unsafe Java objects deserialization
- repo: naver/ngrinder  commit: 85efa4a075354e077a700262ef78e2e9119881bf
- entry CWE: ['CWE-502']  finding CWEs: ['CWE-502']
- rule: object-deserialization
- finding: ngrinder-core/src/main/java/net/grinder/communication/Connector.java:199 method read
- message: Found object deserialization using ObjectInputStream. Deserializing entire Java objects is dangerous because malicious actors can create Java object streams with unintended consequences. Ensure that the objects being deserialized are not user-controlled. If this must be done, consider using HMACs to sign the data stream to make sure it is not tampered with, or consider only transmitting object fields and populating a new object.

```java
public final class Connector {

	static ConnectDetails read(InputStream in) throws CommunicationException {

		try {
			final ObjectInputStream objectInputStream = new ObjectInputStream(in);
			final ConnectionType type =
				(ConnectionType) objectInputStream.readObject();
			final Address address = (Address) objectInputStream.readObject();
			return new ConnectDetails(type, address);
		}
		catch (IOException e) {
			throw new CommunicationException("Could not read address details", e);
		}
		catch (ClassNotFoundException e) {
			throw new CommunicationException("Could not read address details", e);
		}
	}
```

```diff
@@ -23,6 +23,7 @@
 import java.io.InputStream;
+import java.io.ObjectInputFilter;
 import java.io.ObjectInputStream;
@@ -31,6 +32,8 @@
 import net.grinder.common.UncheckedInterruptedException;
+import net.grinder.common.processidentity.ProcessIdentity;
+import net.grinder.engine.controller.AbstractAgentControllerIdentityImplementation;
 
@@ -197,6 +200,23 @@ static ConnectDetails read(InputStream in) throws CommunicationException {
 			final ObjectInputStream objectInputStream = new ObjectInputStream(in);
+			objectInputStream.setObjectInputFilter(filterInfo -> {
+				if (filterInfo.serialClass() == null) {
+					return ObjectInputFilter.Status.UNDECIDED;
+				}
+
+				if (Address.class.isAssignableFrom(filterInfo.serialClass())
+					|| ConnectionType.class.isAssignableFrom(filterInfo.serialClass())
+					|| Enum.class.isAssignableFrom(filterInfo.serialClass())
+					|| filterInfo.serialClass().getCanonicalName().startsWith("net.grinder.engine")
+					|| filterInfo.serialClass().getCanonicalName().startsWith("net.grinder.common")
+				) {
+					return ObjectInputFilter.Status.ALLOWED;
+				}
+
+				return ObjectInputFilter.Status.REJECTED;
+			});
+
 			final ConnectionType type =
```

## 42. GHSA-jmw5-58c7-587h:java.lang.security.audit.crypto.unencrypted-socket.unencrypted-socket:collector/log4j-socket/src/main/java/org/apache/karaf/decanter/collector/log/socket/SocketCollector.java:78

- tags: off-CWE, hunk
- advisory: Apache Karaf Decanter has Deserialization of Untrusted Data in its Log Socket Collector
- repo: apache/karaf-decanter  commit: 9d7058d37160a16aaad34b488170adf277351e8b
- entry CWE: ['CWE-502']  finding CWEs: ['CWE-319']
- rule: unencrypted-socket
- finding: collector/log4j-socket/src/main/java/org/apache/karaf/decanter/collector/log/socket/SocketCollector.java:78 method activate
- message: Detected use of a Java socket that is not encrypted. As a result, the traffic could be read by an attacker intercepting the network traffic. Use an SSLSocket created by 'SSLSocketFactory' or 'SSLServerSocketFactory' instead.

```java
public class SocketCollector implements Closeable, Runnable {

    public void activate(ComponentContext context) throws IOException {
        this.properties = context.getProperties();
        int port = Integer.parseInt(getProperty(this.properties, PORT_NAME, "4560"));
        int workers = Integer.parseInt(getProperty(this.properties, WORKERS_NAME, "10"));
        LOGGER.info("Starting Log4j Socket collector on port {}", port);
        this.serverSocket = new ServerSocket(port);
        // adding 1 for serverSocket handling
        this.executor = Executors.newFixedThreadPool(workers + 1);
        this.executor.execute(this);
        this.open = true;
    }
```

```diff
@@ -18,15 +18,18 @@
 import java.io.Closeable;
+import java.io.DataInputStream;
+import java.io.DataOutputStream;
 import java.io.EOFException;
 import java.io.InputStream;
-import java.io.InvalidClassException;
+import java.io.ObjectInputFilter;
 import java.io.ObjectInputStream;
-import java.io.ObjectStreamClass;
+import java.net.InetAddress;
 import java.net.ServerSocket;
 import java.net.UnknownHostException;
+import java.nio.charset.StandardCharsets;
 import java.util.Dictionary;
@@ -56,8 +59,12 @@
 
+    public static final String HOSTNAME = "hostname";
     public static final String PORT_NAME = "port";
+    public static final String BACKLOG = "backlog";
     public static final String WORKERS_NAME = "workers";
+    public static final String USERNAME = "username";
+    public static final String PASSWORD = "password";
 
@@ -68,14 +75,16 @@ public class SocketCollector implements Closeable, Runnable {
 
-    @SuppressWarnings("unchecked")
     @Activate
         this.properties = context.getProperties();
+        String hostname = getProperty(this.properties, HOSTNAME, "localhost");
         int port = Integer.parseInt(getProperty(this.properties, PORT_NAME, "4560"));
+        int backlog = Integer.parseInt(getProperty(this.properties, BACKLOG, "50"));
         int workers = Integer.parseInt(getProperty(this.properties, WORKERS_NAME, "10"));
-        LOGGER.info("Starting Log4j Socket collector on port {}", port);
-        this.serverSocket = new ServerSocket(port);
+        LOGGER.info("Starting Log4j Socket collector on {}:{}", hostname, port);
+        InetAddress host = InetAddress.getByName(hostname);
+        this.serverSocket = new ServerSocket(port, backlog, host);
         // adding 1 for serverSocket handling
@@ -201,16 +210,26 @@ public SocketRunnable(Socket clientSocket) {
         public void run() {
-            try (ObjectInputStream ois = new LoggingEventObjectInputStream(new BufferedInputStream(clientSocket
-                .getInputStream()))) {
-                while (open) {
-                    try {
-                        Object event = ois.readObject();
-                        if (event instanceof LoggingEvent) {
-                            handleLog4j((LoggingEvent)event);
+            try {
+                InputStream socketInputStream = new BufferedInputStream(clientSocket.getInputStream());
+                
+                // Perform authentication if configured
+                if (!authenticate(socketInputStream)) {
+                    LOGGER.warn("Authentication failed for client at {}", clientSocket.getInetAddress());
+                    return;
+                }
+
+                // After successful authentication, proceed with normal log event processing
+                try (ObjectInputStream ois = new LoggingEventObjectInputStream(socketInputStream)) {
+                    while (open) {
+                        try {
+                            Object event = ois.readObject();
+                            if (event instanceof LoggingEvent) {
+                                handleLog4j((LoggingEvent)event);
+                            }
+                        } catch (ClassNotFoundException e) {
+                            LOGGER.warn("Unable to deserialize event from " + clientSocket.getInetAddress(), e);
                         }
-                    } catch (ClassNotFoundException e) {
-                        LOGGER.warn("Unable to deserialize event from " + clientSocket.getInetAddress(), e);
... (truncated)
```

## 43. GHSA-jqfv-jrvq-95jm:java.lang.security.audit.xxe.transformerfactory-dtds-not-disabled.transformerfactory-dtds-not-disabled:fop-core/src/main/java/org/apache/fop/cli/InputHandler.java:272

- tags: method-only
- advisory: Apache XML Graphics FOP XML External Entity Reference ('XXE') vulnerability
- repo: apache/xmlgraphics-fop  commit: d96ba9a11710d02716b6f4f6107ebfa9ccec7134
- entry CWE: ['CWE-611']  finding CWEs: ['CWE-611']
- rule: transformerfactory-dtds-not-disabled
- finding: fop-core/src/main/java/org/apache/fop/cli/InputHandler.java:272 method transformTo
- message: DOCTYPE declarations are enabled for this TransformerFactory. This is vulnerable to XML external entity attacks. Disable this by setting the attributes "accessExternalDTD" and "accessExternalStylesheet" to "".

```java
public class InputHandler implements ErrorListener, Renderable {

    protected void transformTo(Result result) throws FOPException {
        try {
            // Setup XSLT
            TransformerFactory factory = TransformerFactory.newInstance();
            Transformer transformer;

            Source xsltSource = createXSLTSource();
            if (xsltSource == null) {   // FO Input
                transformer = factory.newTransformer();
            } else {    // XML/XSLT input
                transformer = factory.newTransformer(xsltSource);

                // Set the value of parameters, if any, defined for stylesheet
                if (xsltParams != null) {
                    for (int i = 0; i < xsltParams.size(); i += 2) {
                        transformer.setParameter((String) xsltParams.elementAt(i),
                            (String) xsltParams.elementAt(i + 1));
                    }
                }
                if (uriResolver != null) {
                    transformer.setURIResolver(uriResolver);
                }
            }
            transformer.setErrorListener(this);

            // Create a SAXSource from the input Source file
            Source src = createMainSource();

            // Start XSLT transformation and FOP processing
            transformer.transform(src, result);

        } catch (Exception e) {
            throw new FOPException(e);
        }
    }
```

```diff
@@ -26,6 +26,7 @@
 
+import javax.xml.XMLConstants;
 import javax.xml.parsers.ParserConfigurationException;
@@ -265,6 +266,7 @@ protected void transformTo(Result result) throws FOPException {
             TransformerFactory factory = TransformerFactory.newInstance();
+            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
             Transformer transformer;
```

## 44. GHSA-jqfv-jrvq-95jm:java.lang.security.audit.xxe.transformerfactory-dtds-not-disabled.transformerfactory-dtds-not-disabled:fop-core/src/main/java/org/apache/fop/cli/InputHandler.java:274

- tags: method-only
- advisory: Apache XML Graphics FOP XML External Entity Reference ('XXE') vulnerability
- repo: apache/xmlgraphics-fop  commit: d96ba9a11710d02716b6f4f6107ebfa9ccec7134
- entry CWE: ['CWE-611']  finding CWEs: ['CWE-611']
- rule: transformerfactory-dtds-not-disabled
- finding: fop-core/src/main/java/org/apache/fop/cli/InputHandler.java:274 method transformTo
- message: DOCTYPE declarations are enabled for this TransformerFactory. This is vulnerable to XML external entity attacks. Disable this by setting the attributes "accessExternalDTD" and "accessExternalStylesheet" to "".

```java
public class InputHandler implements ErrorListener, Renderable {

    protected void transformTo(Result result) throws FOPException {
        try {
            // Setup XSLT
            TransformerFactory factory = TransformerFactory.newInstance();
            Transformer transformer;

            Source xsltSource = createXSLTSource();
            if (xsltSource == null) {   // FO Input
                transformer = factory.newTransformer();
            } else {    // XML/XSLT input
                transformer = factory.newTransformer(xsltSource);

                // Set the value of parameters, if any, defined for stylesheet
                if (xsltParams != null) {
                    for (int i = 0; i < xsltParams.size(); i += 2) {
                        transformer.setParameter((String) xsltParams.elementAt(i),
                            (String) xsltParams.elementAt(i + 1));
                    }
                }
                if (uriResolver != null) {
                    transformer.setURIResolver(uriResolver);
                }
            }
            transformer.setErrorListener(this);

            // Create a SAXSource from the input Source file
            Source src = createMainSource();

            // Start XSLT transformation and FOP processing
            transformer.transform(src, result);

        } catch (Exception e) {
            throw new FOPException(e);
        }
    }
```

```diff
@@ -26,6 +26,7 @@
 
+import javax.xml.XMLConstants;
 import javax.xml.parsers.ParserConfigurationException;
@@ -265,6 +266,7 @@ protected void transformTo(Result result) throws FOPException {
             TransformerFactory factory = TransformerFactory.newInstance();
+            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
             Transformer transformer;
```

## 45. GHSA-m964-fjrh-xxq2:java.lang.security.audit.object-deserialization.object-deserialization:server/src/main/java/org/apache/seata/server/cluster/raft/sync/RaftSyncMessageSerializer.java:65

- tags: on-CWE-sample, hunk
- advisory: Apache Seata Vulnerable to Deserialization of Untrusted Data
- repo: apache/incubator-seata  commit: 20cd9625d23f99b71fefc83b8db96c14092a9950
- entry CWE: ['CWE-502']  finding CWEs: ['CWE-502']
- rule: object-deserialization
- finding: server/src/main/java/org/apache/seata/server/cluster/raft/sync/RaftSyncMessageSerializer.java:65 method decode
- message: Found object deserialization using ObjectInputStream. Deserializing entire Java objects is dangerous because malicious actors can create Java object streams with unintended consequences. Ensure that the objects being deserialized are not user-controlled. If this must be done, consider using HMACs to sign the data stream to make sure it is not tampered with, or consider only transmitting object fields and populating a new object.

```java
public class RaftSyncMessageSerializer {

    public static RaftSyncMessage decode(byte[] raftSyncMsgByte) {
        try (ByteArrayInputStream bin = new ByteArrayInputStream(raftSyncMsgByte);
                ObjectInputStream ois = new ObjectInputStream(bin)) {
            Object object = ois.readObject();
            RaftSyncMessage raftSyncMessage;
            if (object instanceof io.seata.server.cluster.raft.sync.msg.RaftSyncMessage) {
                io.seata.server.cluster.raft.sync.msg.RaftSyncMessage oldRaftSyncMessage =
                        (io.seata.server.cluster.raft.sync.msg.RaftSyncMessage)object;
                raftSyncMessage = new RaftSyncMessage();
                raftSyncMessage.setCodec(oldRaftSyncMessage.getCodec());
                raftSyncMessage.setCompressor(oldRaftSyncMessage.getCompressor());
                raftSyncMessage.setVersion(oldRaftSyncMessage.getVersion());
                raftSyncMessage.setBody(oldRaftSyncMessage.getBody());
            } else {
                raftSyncMessage = (RaftSyncMessage)object;
            }
            Serializer serializer = EnhancedServiceLoader.load(Serializer.class,
                    SerializerType.getByCode(raftSyncMessage.getCodec()).name());
            Optional.ofNullable(raftSyncMessage.getBody())
                    .ifPresent(value -> raftSyncMessage.setBody(serializer.deserialize(CompressorFactory
                            .getCompressor(raftSyncMessage.getCompressor()).decompress((byte[])raftSyncMessage.getBody()))));
            return raftSyncMessage;
        } catch (ClassNotFoundException | IOException e) {
            LOGGER.info("Failed to read raft synchronization log: {}", e.getMessage(), e);
            throw new RuntimeException(e);
        }
    }
```

```diff
@@ -21,7 +21,12 @@
 import java.io.ObjectOutputStream;
+import java.io.ObjectStreamClass;
+import java.util.ArrayList;
+import java.util.List;
 import java.util.Optional;
+import org.apache.seata.common.exception.ErrorCode;
+import org.apache.seata.common.exception.SeataRuntimeException;
 import org.apache.seata.common.loader.EnhancedServiceLoader;
@@ -36,6 +41,14 @@ public class RaftSyncMessageSerializer {
 
+    private static final List<String> PERMITS = new ArrayList<>();
+
+    static {
+        PERMITS.add(RaftSyncMessage.class.getName());
+        PERMITS.add(io.seata.server.cluster.raft.sync.msg.RaftSyncMessage.class.getName());
+        PERMITS.add("[B");
+    }
+
     public static byte[] encode(RaftSyncMessage raftSyncMessage) throws IOException {
@@ -62,12 +75,22 @@ public static byte[] encode(io.seata.server.cluster.raft.sync.msg.RaftSyncMessag
         try (ByteArrayInputStream bin = new ByteArrayInputStream(raftSyncMsgByte);
-                ObjectInputStream ois = new ObjectInputStream(bin)) {
+            ObjectInputStream ois = new ObjectInputStream(bin) {
+                @Override
+                protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
+                    if (!PERMITS.contains(desc.getName())) {
+                        throw new SeataRuntimeException(ErrorCode.ERR_DESERIALIZATION_SECURITY,
+                            "Failed to deserialize object: " + desc.getName() + " is not permitted");
+                    }
+
+                    return super.resolveClass(desc);
+                }
+            }) {
             Object object = ois.readObject();
                 io.seata.server.cluster.raft.sync.msg.RaftSyncMessage oldRaftSyncMessage =
-                        (io.seata.server.cluster.raft.sync.msg.RaftSyncMessage)object;
+                    (io.seata.server.cluster.raft.sync.msg.RaftSyncMessage)object;
                 raftSyncMessage = new RaftSyncMessage();
@@ -77,13 +100,16 @@ public static RaftSyncMessage decode(byte[] raftSyncMsgByte) {
             Serializer serializer = EnhancedServiceLoader.load(Serializer.class,
-                    SerializerType.getByCode(raftSyncMessage.getCodec()).name());
+                SerializerType.getByCode(raftSyncMessage.getCodec()).name());
             Optional.ofNullable(raftSyncMessage.getBody())
-                    .ifPresent(value -> raftSyncMessage.setBody(serializer.deserialize(CompressorFactory
-                            .getCompressor(raftSyncMessage.getCompressor()).decompress((byte[])raftSyncMessage.getBody()))));
+                .ifPresent(value -> raftSyncMessage.setBody(serializer.deserialize(CompressorFactory
+                    .getCompressor(raftSyncMessage.getCompressor()).decompress((byte[])raftSyncMessage.getBody()))));
             return raftSyncMessage;
-        } catch (ClassNotFoundException | IOException e) {
+        } catch (Exception e) {
             LOGGER.info("Failed to read raft synchronization log: {}", e.getMessage(), e);
+            if (e instanceof SeataRuntimeException) {
+                throw (SeataRuntimeException)e;
+            }
             throw new RuntimeException(e);
```

## 46. GHSA-qrp9-23p7-g5mf:java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing.documentbuilderfactory-disallow-doctype-decl-missing:contrib/views/wfmanager/src/main/java/org/apache/oozie/ambari/view/Utils.java:67

- tags: method-only
- advisory: Apache Ambari XML External Entity injection
- repo: apache/ambari  commit: d9652e4611ea36208d5f748028b3a9cd980e6edb
- entry CWE: ['CWE-611']  finding CWEs: ['CWE-611']
- rule: documentbuilderfactory-disallow-doctype-decl-missing
- finding: contrib/views/wfmanager/src/main/java/org/apache/oozie/ambari/view/Utils.java:67 method formatXml
- message: DOCTYPE declarations are enabled for this DocumentBuilderFactory. This is vulnerable to XML external entity attacks. Disable this by setting the feature "http://apache.org/xml/features/disallow-doctype-decl" to true. Alternatively, allow DOCTYPE declarations and only prohibit external entities declarations. This can be done by setting the features "http://xml.org/sax/features/external-general-entities" and "http://xml.org/sax/features/external-parameter-entities" to false.

```java
public class Utils {

	public String formatXml(String xml) {

		try {
			DocumentBuilder db = dbf.newDocumentBuilder();
			StreamResult result = new StreamResult(new StringWriter());
			Document document = db
					.parse(new InputSource(new StringReader(xml)));
			Transformer transformer = TransformerFactory.newInstance()
					.newTransformer();
			transformer.setOutputProperty(OutputKeys.INDENT, "yes");
			transformer.setOutputProperty(XML_INDENT_AMT_PROP_NAME,
					XML_INDENT_SPACES);
			DOMSource source = new DOMSource(document);
			transformer.transform(source, result);
			return result.getWriter().toString();
		} catch (ParserConfigurationException | SAXException | IOException
				| TransformerFactoryConfigurationError | TransformerException e) {
			LOGGER.error("Error in formatting xml", e);
			throw new RuntimeException(e);
		}
	}
```

```diff
@@ -58,9 +58,20 @@
 	private static final String XML_INDENT_AMT_PROP_NAME = "{http://xml.apache.org/xslt}indent-amount";
+	private final String FEATURES_DISALLOW_DOCTYPE = "http://apache.org/xml/features/disallow-doctype-decl";
 	private final static Logger LOGGER = LoggerFactory
 	private final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
+	Utils() {
+		// Refer to https://docs.oracle.com/javase/8/docs/api/javax/xml/parsers/DocumentBuilderFactory.html#setFeature-java.lang.String-boolean-
+		try{
+			dbf.setFeature(FEATURES_DISALLOW_DOCTYPE, true);
+			LOGGER.info("Setting feature disallow doctype to true");
+		} catch (ParserConfigurationException | TransformerFactoryConfigurationError e) {
+			LOGGER.error("Error in formatting xml", e);
+			throw new RuntimeException(e);
+		}
+	}
 	public String formatXml(String xml) {
```

## 47. GHSA-rpj9-pc39-h8j8:java.lang.security.audit.xxe.transformerfactory-dtds-not-disabled.transformerfactory-dtds-not-disabled:portal-impl/src/com/liferay/portlet/xslcontent/util/XSLContentUtil.java:54

- tags: off-CWE, method-only
- advisory: Liferay Portal vulnerable to arbitrary command injection
- repo: liferay/liferay-portal  commit: 55502ca16019e1ea1a581ee87f4f20cde638c825
- entry CWE: ['CWE-77']  finding CWEs: ['CWE-611']
- rule: transformerfactory-dtds-not-disabled
- finding: portal-impl/src/com/liferay/portlet/xslcontent/util/XSLContentUtil.java:54 method transform
- message: DOCTYPE declarations are enabled for this TransformerFactory. This is vulnerable to XML external entity attacks. Disable this by setting the attributes "accessExternalDTD" and "accessExternalStylesheet" to "".

```java
public class XSLContentUtil {

	public static String transform(URL xmlUrl, URL xslUrl)
		throws IOException, TransformerException {

		String xml = HttpUtil.URLtoString(xmlUrl);
		String xsl = HttpUtil.URLtoString(xslUrl);

		StreamSource xmlSource = new StreamSource(new UnsyncStringReader(xml));
		StreamSource xslSource = new StreamSource(new UnsyncStringReader(xsl));

		TransformerFactory transformerFactory =
			TransformerFactory.newInstance();

		Transformer transformer =
			transformerFactory.newTransformer(xslSource);

		UnsyncByteArrayOutputStream unsyncByteArrayOutputStream =
			new UnsyncByteArrayOutputStream();

		transformer.transform(
			xmlSource, new StreamResult(unsyncByteArrayOutputStream));

		return unsyncByteArrayOutputStream.toString();
	}
```

```diff
@@ -17,11 +17,13 @@
 import com.liferay.portal.kernel.util.HttpUtil;
+import com.liferay.portal.util.PropsValues;
 
 
+import javax.xml.XMLConstants;
 import javax.xml.transform.Transformer;
@@ -51,6 +53,10 @@ public static String transform(URL xmlUrl, URL xslUrl)
 
+		transformerFactory.setFeature(
+			XMLConstants.FEATURE_SECURE_PROCESSING,
+			PropsValues.XSL_CONTENT_SECURE_PROCESSING_ENABLED);
+
 		Transformer transformer =
```

## 48. GHSA-v7gr-mqpj-wwh3:java.lang.security.httpservlet-path-traversal.httpservlet-path-traversal:bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:194

- tags: off-CWE, hunk
- advisory: CometVisu Backend for openHAB affected by SSRF/XSS
- repo: openhab/openhab-webui  commit: 531dabfa8311a50d2e740bf4f2b4f2400e78646c
- entry CWE: ['CWE-918']  finding CWEs: ['CWE-22']
- rule: httpservlet-path-traversal
- finding: bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:194 method doPost
- message: Detected a potential path traversal. A malicious actor could control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables in file paths are sanitized. You may also consider using a utility method such as org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path.

```java
public class CometVisuServlet extends HttpServlet {

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        File requestedFile = getRequestedFile(req);
        Matcher match = configStorePattern.matcher(req.getParameter("config"));
        if (requestedFile.getName().endsWith("save_config.php") && match.find() && req.getParameter("type") != null
                && req.getParameter("type").equals("xml")) {
            saveConfig(req, resp);
        } else {
            processPhpRequest(requestedFile, req, resp);
        }
    }
```

```diff
@@ -22,8 +22,6 @@
 import java.net.URLDecoder;
-import java.nio.charset.StandardCharsets;
-import java.nio.file.Files;
 import java.text.DateFormat;
@@ -58,6 +56,7 @@
 
+import org.eclipse.jdt.annotation.Nullable;
 import org.openhab.core.OpenHAB;
@@ -103,7 +102,6 @@ public class CometVisuServlet extends HttpServlet {
     private Pattern sitemapPattern = Pattern.compile(".*/visu_config_?(oh_)?([^\\.]+)?\\.xml");
-    private Pattern configStorePattern = Pattern.compile("config/visu_config_oh_([a-z0-9_]+)\\.xml");
 
@@ -112,10 +110,10 @@ public class CometVisuServlet extends HttpServlet {
     protected File userFileFolder;
-    protected String defaultUserDir;
-    protected PHProvider engine;
-    protected ServletContext servletContext;
-    protected ServletConfig config;
+    protected @Nullable String defaultUserDir;
+    protected @Nullable PHProvider engine;
+    protected @Nullable ServletContext servletContext;
+    protected @Nullable ServletConfig config;
 
@@ -146,11 +144,13 @@ public void unsetPHProvider() {
         try {
-            this.engine.createQuercusEngine();
-            this.engine.setIni("include_path", ".:" + rootFolder.getAbsolutePath());
-            if (servletContext != null) {
-                this.engine.init(rootFolder.getAbsolutePath(), defaultUserDir, servletContext);
-                phpEnabled = true;
+            if (this.engine != null) {
+                this.engine.createQuercusEngine();
+                this.engine.setIni("include_path", ".:" + rootFolder.getAbsolutePath());
+                if (servletContext != null) {
+                    this.engine.init(rootFolder.getAbsolutePath(), defaultUserDir, servletContext);
+                    phpEnabled = true;
+                }
             }
@@ -170,10 +170,12 @@ public boolean isPhpEnabled() {
     @Override
-    public final void init(ServletConfig config) throws ServletException {
+    public final void init(@Nullable ServletConfig config) throws ServletException {
         super.init(config);
         this.config = config;
-        servletContext = config.getServletContext();
+        if (config != null) {
+            servletContext = config.getServletContext();
+        }
 
@@ -192,16 +194,10 @@ public final void init(ServletConfig config) throws ServletException {
         File requestedFile = getRequestedFile(req);
-        Matcher match = configStorePattern.matcher(req.getParameter("config"));
-        if (requestedFile.getName().endsWith("save_config.php") && match.find() && req.getParameter("type") != null
-                && req.getParameter("type").equals("xml")) {
-            saveConfig(req, resp);
-        } else {
-            processPhpRequest(requestedFile, req, resp);
-        }
+        processPhpRequest(requestedFile, req, resp);
     }
 
-    private Sitemap getSitemap(String sitemapname) {
+    private @Nullable Sitemap getSitemap(String sitemapname) {
         for (SitemapProvider provider : cometVisuApp.getSitemapProviders()) {
@@ -222,13 +218,14 @@ private Sitemap getSitemap(String sitemapname) {
 
-        String path = req.getPathInfo() != null ? req.getPathInfo() : "/index.html";
+        String path = req.getPathInfo();
+        if (path == null) {
... (truncated)
```

## 49. GHSA-v7gr-mqpj-wwh3:java.lang.security.httpservlet-path-traversal.httpservlet-path-traversal:bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:223

- tags: off-CWE, hunk
- advisory: CometVisu Backend for openHAB affected by SSRF/XSS
- repo: openhab/openhab-webui  commit: 531dabfa8311a50d2e740bf4f2b4f2400e78646c
- entry CWE: ['CWE-918']  finding CWEs: ['CWE-22']
- rule: httpservlet-path-traversal
- finding: bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:223 method doGet
- message: Detected a potential path traversal. A malicious actor could control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables in file paths are sanitized. You may also consider using a utility method such as org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path.

```java
public class CometVisuServlet extends HttpServlet {

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        File requestedFile = getRequestedFile(req);

        String path = req.getPathInfo() != null ? req.getPathInfo() : "/index.html";
        Matcher matcher = sitemapPattern.matcher(path);
        if (matcher.find()) {
            // add headers for cometvisu clients autoconfiguration
            resp.setHeader("X-CometVisu-Backend-LoginUrl",
                    "/rest/" + Config.COMETVISU_BACKEND_ALIAS + "/" + Config.COMETVISU_BACKEND_LOGIN_ALIAS);
            resp.setHeader("X-CometVisu-Backend-Name", "openhab2");

            // serve autogenerated config from openhab sitemap if no real config file exists
            if (!requestedFile.exists()) {
                Sitemap sitemap = getSitemap(matcher.group(2));
                if (sitemap != null) {
                    logger.debug("reading sitemap '{}'", sitemap);
                    VisuConfig config = new VisuConfig(sitemap, cometVisuApp);

                    resp.setContentType(MediaType.APPLICATION_XML);
                    resp.getWriter().write(config.getConfigXml(req));
                    resp.flushBuffer();

                    return;
                } else {
                    logger.debug("Config file not found. Neither as normal config ('{}') nor as sitemap ('{}.sitemap')",
                            requestedFile, matcher.group(2));
                    resp.sendError(HttpServletResponse.SC_NOT_FOUND);
                    return;
                }
            }
        }
        if (requestedFile.getName().equalsIgnoreCase("hidden.php")) {
            // do not deliver the hidden php
            resp.sendError(HttpServletResponse.SC_FORBIDDEN);
        } else if (path.matches(".*editor/dataproviders/.+\\.(php|json)$")
                || path.matches(".*designs/get_designs\\.php$")) {
            dataProviderService(requestedFile, req, resp);
        } else if (path.endsWith(rssLogPath)) {
            processRssLogRequest(requestedFile, req, resp);
        } else if (requestedFile.getName().endsWith(".php")) {
            processPhpRequest(requestedFile, req, resp);
        } else {
            processStaticRequest(requestedFile, req, resp, true);
        }
    }
```

```diff
@@ -22,8 +22,6 @@
 import java.net.URLDecoder;
-import java.nio.charset.StandardCharsets;
-import java.nio.file.Files;
 import java.text.DateFormat;
@@ -58,6 +56,7 @@
 
+import org.eclipse.jdt.annotation.Nullable;
 import org.openhab.core.OpenHAB;
@@ -103,7 +102,6 @@ public class CometVisuServlet extends HttpServlet {
     private Pattern sitemapPattern = Pattern.compile(".*/visu_config_?(oh_)?([^\\.]+)?\\.xml");
-    private Pattern configStorePattern = Pattern.compile("config/visu_config_oh_([a-z0-9_]+)\\.xml");
 
@@ -112,10 +110,10 @@ public class CometVisuServlet extends HttpServlet {
     protected File userFileFolder;
-    protected String defaultUserDir;
-    protected PHProvider engine;
-    protected ServletContext servletContext;
-    protected ServletConfig config;
+    protected @Nullable String defaultUserDir;
+    protected @Nullable PHProvider engine;
+    protected @Nullable ServletContext servletContext;
+    protected @Nullable ServletConfig config;
 
@@ -146,11 +144,13 @@ public void unsetPHProvider() {
         try {
-            this.engine.createQuercusEngine();
-            this.engine.setIni("include_path", ".:" + rootFolder.getAbsolutePath());
-            if (servletContext != null) {
-                this.engine.init(rootFolder.getAbsolutePath(), defaultUserDir, servletContext);
-                phpEnabled = true;
+            if (this.engine != null) {
+                this.engine.createQuercusEngine();
+                this.engine.setIni("include_path", ".:" + rootFolder.getAbsolutePath());
+                if (servletContext != null) {
+                    this.engine.init(rootFolder.getAbsolutePath(), defaultUserDir, servletContext);
+                    phpEnabled = true;
+                }
             }
@@ -170,10 +170,12 @@ public boolean isPhpEnabled() {
     @Override
-    public final void init(ServletConfig config) throws ServletException {
+    public final void init(@Nullable ServletConfig config) throws ServletException {
         super.init(config);
         this.config = config;
-        servletContext = config.getServletContext();
+        if (config != null) {
+            servletContext = config.getServletContext();
+        }
 
@@ -192,16 +194,10 @@ public final void init(ServletConfig config) throws ServletException {
         File requestedFile = getRequestedFile(req);
-        Matcher match = configStorePattern.matcher(req.getParameter("config"));
-        if (requestedFile.getName().endsWith("save_config.php") && match.find() && req.getParameter("type") != null
-                && req.getParameter("type").equals("xml")) {
-            saveConfig(req, resp);
-        } else {
-            processPhpRequest(requestedFile, req, resp);
-        }
+        processPhpRequest(requestedFile, req, resp);
     }
 
-    private Sitemap getSitemap(String sitemapname) {
+    private @Nullable Sitemap getSitemap(String sitemapname) {
         for (SitemapProvider provider : cometVisuApp.getSitemapProviders()) {
@@ -222,13 +218,14 @@ private Sitemap getSitemap(String sitemapname) {
 
-        String path = req.getPathInfo() != null ? req.getPathInfo() : "/index.html";
+        String path = req.getPathInfo();
+        if (path == null) {
... (truncated)
```

## 50. GHSA-v7gr-mqpj-wwh3:java.lang.security.httpservlet-path-traversal.httpservlet-path-traversal:bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:291

- tags: off-CWE, method-only
- advisory: CometVisu Backend for openHAB affected by SSRF/XSS
- repo: openhab/openhab-webui  commit: 531dabfa8311a50d2e740bf4f2b4f2400e78646c
- entry CWE: ['CWE-918']  finding CWEs: ['CWE-22']
- rule: httpservlet-path-traversal
- finding: bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:291 method getRequestedFile
- message: Detected a potential path traversal. A malicious actor could control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables in file paths are sanitized. You may also consider using a utility method such as org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path.

```java
public class CometVisuServlet extends HttpServlet {

    protected File getRequestedFile(HttpServletRequest req) throws UnsupportedEncodingException {
        String requestedFile = req.getPathInfo();
        if (requestedFile.endsWith("/")) {
            requestedFile = requestedFile.substring(0, requestedFile.length() - 1);
        }
        File file = null;

        // check services folder if a file exists there
        if (requestedFile != null) {
            file = new File(userFileFolder, URLDecoder.decode(requestedFile, "UTF-8"));
        }
        // serve the file from the cometvisu src directory
        if (file == null || !file.exists() || file.isDirectory()) {
            file = requestedFile != null ? new File(rootFolder, URLDecoder.decode(requestedFile, "UTF-8")) : rootFolder;
        }
        if (file.isDirectory()) {
            // search for an index file
            FilenameFilter filter = new FilenameFilter() {
                @Override
                public boolean accept(File dir, String name) {
                    return name.startsWith("index.") && (name.endsWith(".php") || name.endsWith(".html"));
                }
            };
            for (String dirFile : file.list(filter)) {
                // take the first one found
                file = new File(file, dirFile);
                break;
            }
        }
        return file;
    }
```

```diff
@@ -22,8 +22,6 @@
 import java.net.URLDecoder;
-import java.nio.charset.StandardCharsets;
-import java.nio.file.Files;
 import java.text.DateFormat;
@@ -58,6 +56,7 @@
 
+import org.eclipse.jdt.annotation.Nullable;
 import org.openhab.core.OpenHAB;
@@ -103,7 +102,6 @@ public class CometVisuServlet extends HttpServlet {
     private Pattern sitemapPattern = Pattern.compile(".*/visu_config_?(oh_)?([^\\.]+)?\\.xml");
-    private Pattern configStorePattern = Pattern.compile("config/visu_config_oh_([a-z0-9_]+)\\.xml");
 
@@ -112,10 +110,10 @@ public class CometVisuServlet extends HttpServlet {
     protected File userFileFolder;
-    protected String defaultUserDir;
-    protected PHProvider engine;
-    protected ServletContext servletContext;
-    protected ServletConfig config;
+    protected @Nullable String defaultUserDir;
+    protected @Nullable PHProvider engine;
+    protected @Nullable ServletContext servletContext;
+    protected @Nullable ServletConfig config;
 
@@ -146,11 +144,13 @@ public void unsetPHProvider() {
         try {
-            this.engine.createQuercusEngine();
-            this.engine.setIni("include_path", ".:" + rootFolder.getAbsolutePath());
-            if (servletContext != null) {
-                this.engine.init(rootFolder.getAbsolutePath(), defaultUserDir, servletContext);
-                phpEnabled = true;
+            if (this.engine != null) {
+                this.engine.createQuercusEngine();
+                this.engine.setIni("include_path", ".:" + rootFolder.getAbsolutePath());
+                if (servletContext != null) {
+                    this.engine.init(rootFolder.getAbsolutePath(), defaultUserDir, servletContext);
+                    phpEnabled = true;
+                }
             }
@@ -170,10 +170,12 @@ public boolean isPhpEnabled() {
     @Override
-    public final void init(ServletConfig config) throws ServletException {
+    public final void init(@Nullable ServletConfig config) throws ServletException {
         super.init(config);
         this.config = config;
-        servletContext = config.getServletContext();
+        if (config != null) {
+            servletContext = config.getServletContext();
+        }
 
@@ -192,16 +194,10 @@ public final void init(ServletConfig config) throws ServletException {
         File requestedFile = getRequestedFile(req);
-        Matcher match = configStorePattern.matcher(req.getParameter("config"));
-        if (requestedFile.getName().endsWith("save_config.php") && match.find() && req.getParameter("type") != null
-                && req.getParameter("type").equals("xml")) {
-            saveConfig(req, resp);
-        } else {
-            processPhpRequest(requestedFile, req, resp);
-        }
+        processPhpRequest(requestedFile, req, resp);
     }
 
-    private Sitemap getSitemap(String sitemapname) {
+    private @Nullable Sitemap getSitemap(String sitemapname) {
         for (SitemapProvider provider : cometVisuApp.getSitemapProviders()) {
@@ -222,13 +218,14 @@ private Sitemap getSitemap(String sitemapname) {
 
-        String path = req.getPathInfo() != null ? req.getPathInfo() : "/index.html";
+        String path = req.getPathInfo();
+        if (path == null) {
... (truncated)
```

## 51. GHSA-v7gr-mqpj-wwh3:java.lang.security.httpservlet-path-traversal.httpservlet-path-traversal:bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:295

- tags: off-CWE, method-only
- advisory: CometVisu Backend for openHAB affected by SSRF/XSS
- repo: openhab/openhab-webui  commit: 531dabfa8311a50d2e740bf4f2b4f2400e78646c
- entry CWE: ['CWE-918']  finding CWEs: ['CWE-22']
- rule: httpservlet-path-traversal
- finding: bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:295 method getRequestedFile
- message: Detected a potential path traversal. A malicious actor could control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables in file paths are sanitized. You may also consider using a utility method such as org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path.

```java
public class CometVisuServlet extends HttpServlet {

    protected File getRequestedFile(HttpServletRequest req) throws UnsupportedEncodingException {
        String requestedFile = req.getPathInfo();
        if (requestedFile.endsWith("/")) {
            requestedFile = requestedFile.substring(0, requestedFile.length() - 1);
        }
        File file = null;

        // check services folder if a file exists there
        if (requestedFile != null) {
            file = new File(userFileFolder, URLDecoder.decode(requestedFile, "UTF-8"));
        }
        // serve the file from the cometvisu src directory
        if (file == null || !file.exists() || file.isDirectory()) {
            file = requestedFile != null ? new File(rootFolder, URLDecoder.decode(requestedFile, "UTF-8")) : rootFolder;
        }
        if (file.isDirectory()) {
            // search for an index file
            FilenameFilter filter = new FilenameFilter() {
                @Override
                public boolean accept(File dir, String name) {
                    return name.startsWith("index.") && (name.endsWith(".php") || name.endsWith(".html"));
                }
            };
            for (String dirFile : file.list(filter)) {
                // take the first one found
                file = new File(file, dirFile);
                break;
            }
        }
        return file;
    }
```

```diff
@@ -22,8 +22,6 @@
 import java.net.URLDecoder;
-import java.nio.charset.StandardCharsets;
-import java.nio.file.Files;
 import java.text.DateFormat;
@@ -58,6 +56,7 @@
 
+import org.eclipse.jdt.annotation.Nullable;
 import org.openhab.core.OpenHAB;
@@ -103,7 +102,6 @@ public class CometVisuServlet extends HttpServlet {
     private Pattern sitemapPattern = Pattern.compile(".*/visu_config_?(oh_)?([^\\.]+)?\\.xml");
-    private Pattern configStorePattern = Pattern.compile("config/visu_config_oh_([a-z0-9_]+)\\.xml");
 
@@ -112,10 +110,10 @@ public class CometVisuServlet extends HttpServlet {
     protected File userFileFolder;
-    protected String defaultUserDir;
-    protected PHProvider engine;
-    protected ServletContext servletContext;
-    protected ServletConfig config;
+    protected @Nullable String defaultUserDir;
+    protected @Nullable PHProvider engine;
+    protected @Nullable ServletContext servletContext;
+    protected @Nullable ServletConfig config;
 
@@ -146,11 +144,13 @@ public void unsetPHProvider() {
         try {
-            this.engine.createQuercusEngine();
-            this.engine.setIni("include_path", ".:" + rootFolder.getAbsolutePath());
-            if (servletContext != null) {
-                this.engine.init(rootFolder.getAbsolutePath(), defaultUserDir, servletContext);
-                phpEnabled = true;
+            if (this.engine != null) {
+                this.engine.createQuercusEngine();
+                this.engine.setIni("include_path", ".:" + rootFolder.getAbsolutePath());
+                if (servletContext != null) {
+                    this.engine.init(rootFolder.getAbsolutePath(), defaultUserDir, servletContext);
+                    phpEnabled = true;
+                }
             }
@@ -170,10 +170,12 @@ public boolean isPhpEnabled() {
     @Override
-    public final void init(ServletConfig config) throws ServletException {
+    public final void init(@Nullable ServletConfig config) throws ServletException {
         super.init(config);
         this.config = config;
-        servletContext = config.getServletContext();
+        if (config != null) {
+            servletContext = config.getServletContext();
+        }
 
@@ -192,16 +194,10 @@ public final void init(ServletConfig config) throws ServletException {
         File requestedFile = getRequestedFile(req);
-        Matcher match = configStorePattern.matcher(req.getParameter("config"));
-        if (requestedFile.getName().endsWith("save_config.php") && match.find() && req.getParameter("type") != null
-                && req.getParameter("type").equals("xml")) {
-            saveConfig(req, resp);
-        } else {
-            processPhpRequest(requestedFile, req, resp);
-        }
+        processPhpRequest(requestedFile, req, resp);
     }
 
-    private Sitemap getSitemap(String sitemapname) {
+    private @Nullable Sitemap getSitemap(String sitemapname) {
         for (SitemapProvider provider : cometVisuApp.getSitemapProviders()) {
@@ -222,13 +218,14 @@ private Sitemap getSitemap(String sitemapname) {
 
-        String path = req.getPathInfo() != null ? req.getPathInfo() : "/index.html";
+        String path = req.getPathInfo();
+        if (path == null) {
... (truncated)
```

## 52. GHSA-v7gr-mqpj-wwh3:java.lang.security.httpservlet-path-traversal.httpservlet-path-traversal:bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:307

- tags: off-CWE, method-only
- advisory: CometVisu Backend for openHAB affected by SSRF/XSS
- repo: openhab/openhab-webui  commit: 531dabfa8311a50d2e740bf4f2b4f2400e78646c
- entry CWE: ['CWE-918']  finding CWEs: ['CWE-22']
- rule: httpservlet-path-traversal
- finding: bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:307 method getRequestedFile
- message: Detected a potential path traversal. A malicious actor could control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables in file paths are sanitized. You may also consider using a utility method such as org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path.

```java
public class CometVisuServlet extends HttpServlet {

    protected File getRequestedFile(HttpServletRequest req) throws UnsupportedEncodingException {
        String requestedFile = req.getPathInfo();
        if (requestedFile.endsWith("/")) {
            requestedFile = requestedFile.substring(0, requestedFile.length() - 1);
        }
        File file = null;

        // check services folder if a file exists there
        if (requestedFile != null) {
            file = new File(userFileFolder, URLDecoder.decode(requestedFile, "UTF-8"));
        }
        // serve the file from the cometvisu src directory
        if (file == null || !file.exists() || file.isDirectory()) {
            file = requestedFile != null ? new File(rootFolder, URLDecoder.decode(requestedFile, "UTF-8")) : rootFolder;
        }
        if (file.isDirectory()) {
            // search for an index file
            FilenameFilter filter = new FilenameFilter() {
                @Override
                public boolean accept(File dir, String name) {
                    return name.startsWith("index.") && (name.endsWith(".php") || name.endsWith(".html"));
                }
            };
            for (String dirFile : file.list(filter)) {
                // take the first one found
                file = new File(file, dirFile);
                break;
            }
        }
        return file;
    }
```

```diff
@@ -22,8 +22,6 @@
 import java.net.URLDecoder;
-import java.nio.charset.StandardCharsets;
-import java.nio.file.Files;
 import java.text.DateFormat;
@@ -58,6 +56,7 @@
 
+import org.eclipse.jdt.annotation.Nullable;
 import org.openhab.core.OpenHAB;
@@ -103,7 +102,6 @@ public class CometVisuServlet extends HttpServlet {
     private Pattern sitemapPattern = Pattern.compile(".*/visu_config_?(oh_)?([^\\.]+)?\\.xml");
-    private Pattern configStorePattern = Pattern.compile("config/visu_config_oh_([a-z0-9_]+)\\.xml");
 
@@ -112,10 +110,10 @@ public class CometVisuServlet extends HttpServlet {
     protected File userFileFolder;
-    protected String defaultUserDir;
-    protected PHProvider engine;
-    protected ServletContext servletContext;
-    protected ServletConfig config;
+    protected @Nullable String defaultUserDir;
+    protected @Nullable PHProvider engine;
+    protected @Nullable ServletContext servletContext;
+    protected @Nullable ServletConfig config;
 
@@ -146,11 +144,13 @@ public void unsetPHProvider() {
         try {
-            this.engine.createQuercusEngine();
-            this.engine.setIni("include_path", ".:" + rootFolder.getAbsolutePath());
-            if (servletContext != null) {
-                this.engine.init(rootFolder.getAbsolutePath(), defaultUserDir, servletContext);
-                phpEnabled = true;
+            if (this.engine != null) {
+                this.engine.createQuercusEngine();
+                this.engine.setIni("include_path", ".:" + rootFolder.getAbsolutePath());
+                if (servletContext != null) {
+                    this.engine.init(rootFolder.getAbsolutePath(), defaultUserDir, servletContext);
+                    phpEnabled = true;
+                }
             }
@@ -170,10 +170,12 @@ public boolean isPhpEnabled() {
     @Override
-    public final void init(ServletConfig config) throws ServletException {
+    public final void init(@Nullable ServletConfig config) throws ServletException {
         super.init(config);
         this.config = config;
-        servletContext = config.getServletContext();
+        if (config != null) {
+            servletContext = config.getServletContext();
+        }
 
@@ -192,16 +194,10 @@ public final void init(ServletConfig config) throws ServletException {
         File requestedFile = getRequestedFile(req);
-        Matcher match = configStorePattern.matcher(req.getParameter("config"));
-        if (requestedFile.getName().endsWith("save_config.php") && match.find() && req.getParameter("type") != null
-                && req.getParameter("type").equals("xml")) {
-            saveConfig(req, resp);
-        } else {
-            processPhpRequest(requestedFile, req, resp);
-        }
+        processPhpRequest(requestedFile, req, resp);
     }
 
-    private Sitemap getSitemap(String sitemapname) {
+    private @Nullable Sitemap getSitemap(String sitemapname) {
         for (SitemapProvider provider : cometVisuApp.getSitemapProviders()) {
@@ -222,13 +218,14 @@ private Sitemap getSitemap(String sitemapname) {
 
-        String path = req.getPathInfo() != null ? req.getPathInfo() : "/index.html";
+        String path = req.getPathInfo();
+        if (path == null) {
... (truncated)
```

## 53. GHSA-v7gr-mqpj-wwh3:java.lang.security.httpservlet-path-traversal.httpservlet-path-traversal:bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:545

- tags: off-CWE, hunk
- advisory: CometVisu Backend for openHAB affected by SSRF/XSS
- repo: openhab/openhab-webui  commit: 531dabfa8311a50d2e740bf4f2b4f2400e78646c
- entry CWE: ['CWE-918']  finding CWEs: ['CWE-22']
- rule: httpservlet-path-traversal
- finding: bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:545 method processStaticRequest
- message: Detected a potential path traversal. A malicious actor could control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables in file paths are sanitized. You may also consider using a utility method such as org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path.

```java
public class CometVisuServlet extends HttpServlet {

    private void processStaticRequest(File file, HttpServletRequest request, HttpServletResponse response,
            boolean content) throws IOException {
        // Validate the requested file
        // ------------------------------------------------------------
        if (file == null) {
            // Get requested file by path info.
            String requestedFile = request.getPathInfo();

            // Check if file is actually supplied to the request URL.
            if (requestedFile == null) {
                // Do your thing if the file is not supplied to the request URL.
                // Throw an exception, or send 404, or show default/warning
                // page, or
                // just ignore it.
                response.sendError(HttpServletResponse.SC_NOT_FOUND);
                return;
            }

            // URL-decode the file name (might contain spaces and on) and
            // prepare
            // file object.
            file = new File(rootFolder, URLDecoder.decode(requestedFile, "UTF-8"));
        }
        if (file.equals(rootFolder) || (file.exists() && file.isDirectory())) {
            file = new File(file, "index.html");
        }

        // Check if file actually exists in filesystem.
        if (!file.exists()) {
            // show installation hints if the CometVisu-Clients main index.html is requested but cannot be found
            if (file.getParentFile().equals(rootFolder)
                    && (file.getName().equalsIgnoreCase("index.html") || file.getName().length() == 0)) {
                // looking for CometVisu clients index.html file
                String path = null;
                File folder = file.isDirectory() ? file : file.getParentFile();
                if (folder.exists()) {
                    File index = ClientInstaller.findClientRoot(folder, "index.html");
                    path = index.exists() ? index.getPath().replaceFirst(rootFolder.getPath() + "/", "") : null;
                }
                if (path != null) {
                    // forward to position
                    response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
                    response.setHeader("Location", path + "?" + request.getQueryString());
                } else {
                    showInstallationHint(request, response);
                }
            } else {
                response.sendError(HttpServletResponse.SC_NOT_FOUND);
            }
            return;
        }

        // Prepare some variables. The ETag is an unique identifier of the file.
        String fileName = file.getName();
        long length = file.length();
        long lastModified = file.lastModified();
        String eTag = fileName + "_" + length + "_" + lastModified;
        long expires = System.currentTimeMillis() + DEFAULT_EXPIRE_TIME;

        // Validate request headers for caching
        // ---------------------------------------------------

        // If-None-Match header should contain "*" or ETag. If so, then return
        // 304.
        String ifNoneMatch = request.getHeader("If-None-Match");
        if (ifNoneMatch != null && matches(ifNoneMatch, eTag)) {
            response.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
            response.setHeader("ETag", eTag); // Required in 304.
            response.setDateHeader("Expires", expires); // Postpone cache with 1
                                                        // week.
            return;
        }

        // If-Modified-Since header should be greater than LastModified. If so,
        // then return 304.
        // This header is ignored if any If-None-Match header is specified.
        long ifModifiedSince = request.getDateHeader("If-Modified-Since");
        if (ifNoneMatch == null && ifModifiedSince != -1 && ifModifiedSince + 1000 > lastModified) {
            response.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
            response.setHeader("ETag", eTag); // Required in 304.
            response.setDateHeader("Expires", expires); // Postpone cache with 1
                                                        // week.
            return;
        }

        // Validate request headers for resume
        // ----------------------------------------------------

... (truncated)
```

```diff
@@ -22,8 +22,6 @@
 import java.net.URLDecoder;
-import java.nio.charset.StandardCharsets;
-import java.nio.file.Files;
 import java.text.DateFormat;
@@ -58,6 +56,7 @@
 
+import org.eclipse.jdt.annotation.Nullable;
 import org.openhab.core.OpenHAB;
@@ -103,7 +102,6 @@ public class CometVisuServlet extends HttpServlet {
     private Pattern sitemapPattern = Pattern.compile(".*/visu_config_?(oh_)?([^\\.]+)?\\.xml");
-    private Pattern configStorePattern = Pattern.compile("config/visu_config_oh_([a-z0-9_]+)\\.xml");
 
@@ -112,10 +110,10 @@ public class CometVisuServlet extends HttpServlet {
     protected File userFileFolder;
-    protected String defaultUserDir;
-    protected PHProvider engine;
-    protected ServletContext servletContext;
-    protected ServletConfig config;
+    protected @Nullable String defaultUserDir;
+    protected @Nullable PHProvider engine;
+    protected @Nullable ServletContext servletContext;
+    protected @Nullable ServletConfig config;
 
@@ -146,11 +144,13 @@ public void unsetPHProvider() {
         try {
-            this.engine.createQuercusEngine();
-            this.engine.setIni("include_path", ".:" + rootFolder.getAbsolutePath());
-            if (servletContext != null) {
-                this.engine.init(rootFolder.getAbsolutePath(), defaultUserDir, servletContext);
-                phpEnabled = true;
+            if (this.engine != null) {
+                this.engine.createQuercusEngine();
+                this.engine.setIni("include_path", ".:" + rootFolder.getAbsolutePath());
+                if (servletContext != null) {
+                    this.engine.init(rootFolder.getAbsolutePath(), defaultUserDir, servletContext);
+                    phpEnabled = true;
+                }
             }
@@ -170,10 +170,12 @@ public boolean isPhpEnabled() {
     @Override
-    public final void init(ServletConfig config) throws ServletException {
+    public final void init(@Nullable ServletConfig config) throws ServletException {
         super.init(config);
         this.config = config;
-        servletContext = config.getServletContext();
+        if (config != null) {
+            servletContext = config.getServletContext();
+        }
 
@@ -192,16 +194,10 @@ public final void init(ServletConfig config) throws ServletException {
         File requestedFile = getRequestedFile(req);
-        Matcher match = configStorePattern.matcher(req.getParameter("config"));
-        if (requestedFile.getName().endsWith("save_config.php") && match.find() && req.getParameter("type") != null
-                && req.getParameter("type").equals("xml")) {
-            saveConfig(req, resp);
-        } else {
-            processPhpRequest(requestedFile, req, resp);
-        }
+        processPhpRequest(requestedFile, req, resp);
     }
 
-    private Sitemap getSitemap(String sitemapname) {
+    private @Nullable Sitemap getSitemap(String sitemapname) {
         for (SitemapProvider provider : cometVisuApp.getSitemapProviders()) {
@@ -222,13 +218,14 @@ private Sitemap getSitemap(String sitemapname) {
 
-        String path = req.getPathInfo() != null ? req.getPathInfo() : "/index.html";
+        String path = req.getPathInfo();
+        if (path == null) {
... (truncated)
```

## 54. GHSA-v7gr-mqpj-wwh3:java.lang.security.httpservlet-path-traversal.httpservlet-path-traversal:bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:548

- tags: off-CWE, hunk
- advisory: CometVisu Backend for openHAB affected by SSRF/XSS
- repo: openhab/openhab-webui  commit: 531dabfa8311a50d2e740bf4f2b4f2400e78646c
- entry CWE: ['CWE-918']  finding CWEs: ['CWE-22']
- rule: httpservlet-path-traversal
- finding: bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:548 method processStaticRequest
- message: Detected a potential path traversal. A malicious actor could control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables in file paths are sanitized. You may also consider using a utility method such as org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path.

```java
public class CometVisuServlet extends HttpServlet {

    private void processStaticRequest(File file, HttpServletRequest request, HttpServletResponse response,
            boolean content) throws IOException {
        // Validate the requested file
        // ------------------------------------------------------------
        if (file == null) {
            // Get requested file by path info.
            String requestedFile = request.getPathInfo();

            // Check if file is actually supplied to the request URL.
            if (requestedFile == null) {
                // Do your thing if the file is not supplied to the request URL.
                // Throw an exception, or send 404, or show default/warning
                // page, or
                // just ignore it.
                response.sendError(HttpServletResponse.SC_NOT_FOUND);
                return;
            }

            // URL-decode the file name (might contain spaces and on) and
            // prepare
            // file object.
            file = new File(rootFolder, URLDecoder.decode(requestedFile, "UTF-8"));
        }
        if (file.equals(rootFolder) || (file.exists() && file.isDirectory())) {
            file = new File(file, "index.html");
        }

        // Check if file actually exists in filesystem.
        if (!file.exists()) {
            // show installation hints if the CometVisu-Clients main index.html is requested but cannot be found
            if (file.getParentFile().equals(rootFolder)
                    && (file.getName().equalsIgnoreCase("index.html") || file.getName().length() == 0)) {
                // looking for CometVisu clients index.html file
                String path = null;
                File folder = file.isDirectory() ? file : file.getParentFile();
                if (folder.exists()) {
                    File index = ClientInstaller.findClientRoot(folder, "index.html");
                    path = index.exists() ? index.getPath().replaceFirst(rootFolder.getPath() + "/", "") : null;
                }
                if (path != null) {
                    // forward to position
                    response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
                    response.setHeader("Location", path + "?" + request.getQueryString());
                } else {
                    showInstallationHint(request, response);
                }
            } else {
                response.sendError(HttpServletResponse.SC_NOT_FOUND);
            }
            return;
        }

        // Prepare some variables. The ETag is an unique identifier of the file.
        String fileName = file.getName();
        long length = file.length();
        long lastModified = file.lastModified();
        String eTag = fileName + "_" + length + "_" + lastModified;
        long expires = System.currentTimeMillis() + DEFAULT_EXPIRE_TIME;

        // Validate request headers for caching
        // ---------------------------------------------------

        // If-None-Match header should contain "*" or ETag. If so, then return
        // 304.
        String ifNoneMatch = request.getHeader("If-None-Match");
        if (ifNoneMatch != null && matches(ifNoneMatch, eTag)) {
            response.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
            response.setHeader("ETag", eTag); // Required in 304.
            response.setDateHeader("Expires", expires); // Postpone cache with 1
                                                        // week.
            return;
        }

        // If-Modified-Since header should be greater than LastModified. If so,
        // then return 304.
        // This header is ignored if any If-None-Match header is specified.
        long ifModifiedSince = request.getDateHeader("If-Modified-Since");
        if (ifNoneMatch == null && ifModifiedSince != -1 && ifModifiedSince + 1000 > lastModified) {
            response.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
            response.setHeader("ETag", eTag); // Required in 304.
            response.setDateHeader("Expires", expires); // Postpone cache with 1
                                                        // week.
            return;
        }

        // Validate request headers for resume
        // ----------------------------------------------------

... (truncated)
```

```diff
@@ -22,8 +22,6 @@
 import java.net.URLDecoder;
-import java.nio.charset.StandardCharsets;
-import java.nio.file.Files;
 import java.text.DateFormat;
@@ -58,6 +56,7 @@
 
+import org.eclipse.jdt.annotation.Nullable;
 import org.openhab.core.OpenHAB;
@@ -103,7 +102,6 @@ public class CometVisuServlet extends HttpServlet {
     private Pattern sitemapPattern = Pattern.compile(".*/visu_config_?(oh_)?([^\\.]+)?\\.xml");
-    private Pattern configStorePattern = Pattern.compile("config/visu_config_oh_([a-z0-9_]+)\\.xml");
 
@@ -112,10 +110,10 @@ public class CometVisuServlet extends HttpServlet {
     protected File userFileFolder;
-    protected String defaultUserDir;
-    protected PHProvider engine;
-    protected ServletContext servletContext;
-    protected ServletConfig config;
+    protected @Nullable String defaultUserDir;
+    protected @Nullable PHProvider engine;
+    protected @Nullable ServletContext servletContext;
+    protected @Nullable ServletConfig config;
 
@@ -146,11 +144,13 @@ public void unsetPHProvider() {
         try {
-            this.engine.createQuercusEngine();
-            this.engine.setIni("include_path", ".:" + rootFolder.getAbsolutePath());
-            if (servletContext != null) {
-                this.engine.init(rootFolder.getAbsolutePath(), defaultUserDir, servletContext);
-                phpEnabled = true;
+            if (this.engine != null) {
+                this.engine.createQuercusEngine();
+                this.engine.setIni("include_path", ".:" + rootFolder.getAbsolutePath());
+                if (servletContext != null) {
+                    this.engine.init(rootFolder.getAbsolutePath(), defaultUserDir, servletContext);
+                    phpEnabled = true;
+                }
             }
@@ -170,10 +170,12 @@ public boolean isPhpEnabled() {
     @Override
-    public final void init(ServletConfig config) throws ServletException {
+    public final void init(@Nullable ServletConfig config) throws ServletException {
         super.init(config);
         this.config = config;
-        servletContext = config.getServletContext();
+        if (config != null) {
+            servletContext = config.getServletContext();
+        }
 
@@ -192,16 +194,10 @@ public final void init(ServletConfig config) throws ServletException {
         File requestedFile = getRequestedFile(req);
-        Matcher match = configStorePattern.matcher(req.getParameter("config"));
-        if (requestedFile.getName().endsWith("save_config.php") && match.find() && req.getParameter("type") != null
-                && req.getParameter("type").equals("xml")) {
-            saveConfig(req, resp);
-        } else {
-            processPhpRequest(requestedFile, req, resp);
-        }
+        processPhpRequest(requestedFile, req, resp);
     }
 
-    private Sitemap getSitemap(String sitemapname) {
+    private @Nullable Sitemap getSitemap(String sitemapname) {
         for (SitemapProvider provider : cometVisuApp.getSitemapProviders()) {
@@ -222,13 +218,14 @@ private Sitemap getSitemap(String sitemapname) {
 
-        String path = req.getPathInfo() != null ? req.getPathInfo() : "/index.html";
+        String path = req.getPathInfo();
+        if (path == null) {
... (truncated)
```

## 55. GHSA-v7gr-mqpj-wwh3:java.lang.security.httpservlet-path-traversal.httpservlet-path-traversal:bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:558

- tags: off-CWE, hunk
- advisory: CometVisu Backend for openHAB affected by SSRF/XSS
- repo: openhab/openhab-webui  commit: 531dabfa8311a50d2e740bf4f2b4f2400e78646c
- entry CWE: ['CWE-918']  finding CWEs: ['CWE-22']
- rule: httpservlet-path-traversal
- finding: bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:558 method processStaticRequest
- message: Detected a potential path traversal. A malicious actor could control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables in file paths are sanitized. You may also consider using a utility method such as org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path.

```java
public class CometVisuServlet extends HttpServlet {

    private void processStaticRequest(File file, HttpServletRequest request, HttpServletResponse response,
            boolean content) throws IOException {
        // Validate the requested file
        // ------------------------------------------------------------
        if (file == null) {
            // Get requested file by path info.
            String requestedFile = request.getPathInfo();

            // Check if file is actually supplied to the request URL.
            if (requestedFile == null) {
                // Do your thing if the file is not supplied to the request URL.
                // Throw an exception, or send 404, or show default/warning
                // page, or
                // just ignore it.
                response.sendError(HttpServletResponse.SC_NOT_FOUND);
                return;
            }

            // URL-decode the file name (might contain spaces and on) and
            // prepare
            // file object.
            file = new File(rootFolder, URLDecoder.decode(requestedFile, "UTF-8"));
        }
        if (file.equals(rootFolder) || (file.exists() && file.isDirectory())) {
            file = new File(file, "index.html");
        }

        // Check if file actually exists in filesystem.
        if (!file.exists()) {
            // show installation hints if the CometVisu-Clients main index.html is requested but cannot be found
            if (file.getParentFile().equals(rootFolder)
                    && (file.getName().equalsIgnoreCase("index.html") || file.getName().length() == 0)) {
                // looking for CometVisu clients index.html file
                String path = null;
                File folder = file.isDirectory() ? file : file.getParentFile();
                if (folder.exists()) {
                    File index = ClientInstaller.findClientRoot(folder, "index.html");
                    path = index.exists() ? index.getPath().replaceFirst(rootFolder.getPath() + "/", "") : null;
                }
                if (path != null) {
                    // forward to position
                    response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
                    response.setHeader("Location", path + "?" + request.getQueryString());
                } else {
                    showInstallationHint(request, response);
                }
            } else {
                response.sendError(HttpServletResponse.SC_NOT_FOUND);
            }
            return;
        }

        // Prepare some variables. The ETag is an unique identifier of the file.
        String fileName = file.getName();
        long length = file.length();
        long lastModified = file.lastModified();
        String eTag = fileName + "_" + length + "_" + lastModified;
        long expires = System.currentTimeMillis() + DEFAULT_EXPIRE_TIME;

        // Validate request headers for caching
        // ---------------------------------------------------

        // If-None-Match header should contain "*" or ETag. If so, then return
        // 304.
        String ifNoneMatch = request.getHeader("If-None-Match");
        if (ifNoneMatch != null && matches(ifNoneMatch, eTag)) {
            response.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
            response.setHeader("ETag", eTag); // Required in 304.
            response.setDateHeader("Expires", expires); // Postpone cache with 1
                                                        // week.
            return;
        }

        // If-Modified-Since header should be greater than LastModified. If so,
        // then return 304.
        // This header is ignored if any If-None-Match header is specified.
        long ifModifiedSince = request.getDateHeader("If-Modified-Since");
        if (ifNoneMatch == null && ifModifiedSince != -1 && ifModifiedSince + 1000 > lastModified) {
            response.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
            response.setHeader("ETag", eTag); // Required in 304.
            response.setDateHeader("Expires", expires); // Postpone cache with 1
                                                        // week.
            return;
        }

        // Validate request headers for resume
        // ----------------------------------------------------

... (truncated)
```

```diff
@@ -22,8 +22,6 @@
 import java.net.URLDecoder;
-import java.nio.charset.StandardCharsets;
-import java.nio.file.Files;
 import java.text.DateFormat;
@@ -58,6 +56,7 @@
 
+import org.eclipse.jdt.annotation.Nullable;
 import org.openhab.core.OpenHAB;
@@ -103,7 +102,6 @@ public class CometVisuServlet extends HttpServlet {
     private Pattern sitemapPattern = Pattern.compile(".*/visu_config_?(oh_)?([^\\.]+)?\\.xml");
-    private Pattern configStorePattern = Pattern.compile("config/visu_config_oh_([a-z0-9_]+)\\.xml");
 
@@ -112,10 +110,10 @@ public class CometVisuServlet extends HttpServlet {
     protected File userFileFolder;
-    protected String defaultUserDir;
-    protected PHProvider engine;
-    protected ServletContext servletContext;
-    protected ServletConfig config;
+    protected @Nullable String defaultUserDir;
+    protected @Nullable PHProvider engine;
+    protected @Nullable ServletContext servletContext;
+    protected @Nullable ServletConfig config;
 
@@ -146,11 +144,13 @@ public void unsetPHProvider() {
         try {
-            this.engine.createQuercusEngine();
-            this.engine.setIni("include_path", ".:" + rootFolder.getAbsolutePath());
-            if (servletContext != null) {
-                this.engine.init(rootFolder.getAbsolutePath(), defaultUserDir, servletContext);
-                phpEnabled = true;
+            if (this.engine != null) {
+                this.engine.createQuercusEngine();
+                this.engine.setIni("include_path", ".:" + rootFolder.getAbsolutePath());
+                if (servletContext != null) {
+                    this.engine.init(rootFolder.getAbsolutePath(), defaultUserDir, servletContext);
+                    phpEnabled = true;
+                }
             }
@@ -170,10 +170,12 @@ public boolean isPhpEnabled() {
     @Override
-    public final void init(ServletConfig config) throws ServletException {
+    public final void init(@Nullable ServletConfig config) throws ServletException {
         super.init(config);
         this.config = config;
-        servletContext = config.getServletContext();
+        if (config != null) {
+            servletContext = config.getServletContext();
+        }
 
@@ -192,16 +194,10 @@ public final void init(ServletConfig config) throws ServletException {
         File requestedFile = getRequestedFile(req);
-        Matcher match = configStorePattern.matcher(req.getParameter("config"));
-        if (requestedFile.getName().endsWith("save_config.php") && match.find() && req.getParameter("type") != null
-                && req.getParameter("type").equals("xml")) {
-            saveConfig(req, resp);
-        } else {
-            processPhpRequest(requestedFile, req, resp);
-        }
+        processPhpRequest(requestedFile, req, resp);
     }
 
-    private Sitemap getSitemap(String sitemapname) {
+    private @Nullable Sitemap getSitemap(String sitemapname) {
         for (SitemapProvider provider : cometVisuApp.getSitemapProviders()) {
@@ -222,13 +218,14 @@ private Sitemap getSitemap(String sitemapname) {
 
-        String path = req.getPathInfo() != null ? req.getPathInfo() : "/index.html";
+        String path = req.getPathInfo();
+        if (path == null) {
... (truncated)
```

## 56. GHSA-v7gr-mqpj-wwh3:java.lang.security.httpservlet-path-traversal.httpservlet-path-traversal:bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:560

- tags: off-CWE, hunk
- advisory: CometVisu Backend for openHAB affected by SSRF/XSS
- repo: openhab/openhab-webui  commit: 531dabfa8311a50d2e740bf4f2b4f2400e78646c
- entry CWE: ['CWE-918']  finding CWEs: ['CWE-22']
- rule: httpservlet-path-traversal
- finding: bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:560 method processStaticRequest
- message: Detected a potential path traversal. A malicious actor could control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables in file paths are sanitized. You may also consider using a utility method such as org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path.

```java
public class CometVisuServlet extends HttpServlet {

    private void processStaticRequest(File file, HttpServletRequest request, HttpServletResponse response,
            boolean content) throws IOException {
        // Validate the requested file
        // ------------------------------------------------------------
        if (file == null) {
            // Get requested file by path info.
            String requestedFile = request.getPathInfo();

            // Check if file is actually supplied to the request URL.
            if (requestedFile == null) {
                // Do your thing if the file is not supplied to the request URL.
                // Throw an exception, or send 404, or show default/warning
                // page, or
                // just ignore it.
                response.sendError(HttpServletResponse.SC_NOT_FOUND);
                return;
            }

            // URL-decode the file name (might contain spaces and on) and
            // prepare
            // file object.
            file = new File(rootFolder, URLDecoder.decode(requestedFile, "UTF-8"));
        }
        if (file.equals(rootFolder) || (file.exists() && file.isDirectory())) {
            file = new File(file, "index.html");
        }

        // Check if file actually exists in filesystem.
        if (!file.exists()) {
            // show installation hints if the CometVisu-Clients main index.html is requested but cannot be found
            if (file.getParentFile().equals(rootFolder)
                    && (file.getName().equalsIgnoreCase("index.html") || file.getName().length() == 0)) {
                // looking for CometVisu clients index.html file
                String path = null;
                File folder = file.isDirectory() ? file : file.getParentFile();
                if (folder.exists()) {
                    File index = ClientInstaller.findClientRoot(folder, "index.html");
                    path = index.exists() ? index.getPath().replaceFirst(rootFolder.getPath() + "/", "") : null;
                }
                if (path != null) {
                    // forward to position
                    response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
                    response.setHeader("Location", path + "?" + request.getQueryString());
                } else {
                    showInstallationHint(request, response);
                }
            } else {
                response.sendError(HttpServletResponse.SC_NOT_FOUND);
            }
            return;
        }

        // Prepare some variables. The ETag is an unique identifier of the file.
        String fileName = file.getName();
        long length = file.length();
        long lastModified = file.lastModified();
        String eTag = fileName + "_" + length + "_" + lastModified;
        long expires = System.currentTimeMillis() + DEFAULT_EXPIRE_TIME;

        // Validate request headers for caching
        // ---------------------------------------------------

        // If-None-Match header should contain "*" or ETag. If so, then return
        // 304.
        String ifNoneMatch = request.getHeader("If-None-Match");
        if (ifNoneMatch != null && matches(ifNoneMatch, eTag)) {
            response.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
            response.setHeader("ETag", eTag); // Required in 304.
            response.setDateHeader("Expires", expires); // Postpone cache with 1
                                                        // week.
            return;
        }

        // If-Modified-Since header should be greater than LastModified. If so,
        // then return 304.
        // This header is ignored if any If-None-Match header is specified.
        long ifModifiedSince = request.getDateHeader("If-Modified-Since");
        if (ifNoneMatch == null && ifModifiedSince != -1 && ifModifiedSince + 1000 > lastModified) {
            response.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
            response.setHeader("ETag", eTag); // Required in 304.
            response.setDateHeader("Expires", expires); // Postpone cache with 1
                                                        // week.
            return;
        }

        // Validate request headers for resume
        // ----------------------------------------------------

... (truncated)
```

```diff
@@ -22,8 +22,6 @@
 import java.net.URLDecoder;
-import java.nio.charset.StandardCharsets;
-import java.nio.file.Files;
 import java.text.DateFormat;
@@ -58,6 +56,7 @@
 
+import org.eclipse.jdt.annotation.Nullable;
 import org.openhab.core.OpenHAB;
@@ -103,7 +102,6 @@ public class CometVisuServlet extends HttpServlet {
     private Pattern sitemapPattern = Pattern.compile(".*/visu_config_?(oh_)?([^\\.]+)?\\.xml");
-    private Pattern configStorePattern = Pattern.compile("config/visu_config_oh_([a-z0-9_]+)\\.xml");
 
@@ -112,10 +110,10 @@ public class CometVisuServlet extends HttpServlet {
     protected File userFileFolder;
-    protected String defaultUserDir;
-    protected PHProvider engine;
-    protected ServletContext servletContext;
-    protected ServletConfig config;
+    protected @Nullable String defaultUserDir;
+    protected @Nullable PHProvider engine;
+    protected @Nullable ServletContext servletContext;
+    protected @Nullable ServletConfig config;
 
@@ -146,11 +144,13 @@ public void unsetPHProvider() {
         try {
-            this.engine.createQuercusEngine();
-            this.engine.setIni("include_path", ".:" + rootFolder.getAbsolutePath());
-            if (servletContext != null) {
-                this.engine.init(rootFolder.getAbsolutePath(), defaultUserDir, servletContext);
-                phpEnabled = true;
+            if (this.engine != null) {
+                this.engine.createQuercusEngine();
+                this.engine.setIni("include_path", ".:" + rootFolder.getAbsolutePath());
+                if (servletContext != null) {
+                    this.engine.init(rootFolder.getAbsolutePath(), defaultUserDir, servletContext);
+                    phpEnabled = true;
+                }
             }
@@ -170,10 +170,12 @@ public boolean isPhpEnabled() {
     @Override
-    public final void init(ServletConfig config) throws ServletException {
+    public final void init(@Nullable ServletConfig config) throws ServletException {
         super.init(config);
         this.config = config;
-        servletContext = config.getServletContext();
+        if (config != null) {
+            servletContext = config.getServletContext();
+        }
 
@@ -192,16 +194,10 @@ public final void init(ServletConfig config) throws ServletException {
         File requestedFile = getRequestedFile(req);
-        Matcher match = configStorePattern.matcher(req.getParameter("config"));
-        if (requestedFile.getName().endsWith("save_config.php") && match.find() && req.getParameter("type") != null
-                && req.getParameter("type").equals("xml")) {
-            saveConfig(req, resp);
-        } else {
-            processPhpRequest(requestedFile, req, resp);
-        }
+        processPhpRequest(requestedFile, req, resp);
     }
 
-    private Sitemap getSitemap(String sitemapname) {
+    private @Nullable Sitemap getSitemap(String sitemapname) {
         for (SitemapProvider provider : cometVisuApp.getSitemapProviders()) {
@@ -222,13 +218,14 @@ private Sitemap getSitemap(String sitemapname) {
 
-        String path = req.getPathInfo() != null ? req.getPathInfo() : "/index.html";
+        String path = req.getPathInfo();
+        if (path == null) {
... (truncated)
```

## 57. GHSA-v7gr-mqpj-wwh3:java.lang.security.httpservlet-path-traversal.httpservlet-path-traversal:bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:851

- tags: off-CWE, hunk
- advisory: CometVisu Backend for openHAB affected by SSRF/XSS
- repo: openhab/openhab-webui  commit: 531dabfa8311a50d2e740bf4f2b4f2400e78646c
- entry CWE: ['CWE-918']  finding CWEs: ['CWE-22']
- rule: httpservlet-path-traversal
- finding: bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:851 method saveConfig
- message: Detected a potential path traversal. A malicious actor could control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables in file paths are sanitized. You may also consider using a utility method such as org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path.

```java
public class CometVisuServlet extends HttpServlet {

    private final void saveConfig(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType(MediaType.APPLICATION_JSON);

        class Response {
            public Boolean success = false;
            public String message = "";

            Response() {
            }
        }
        Response resp = new Response();

        String fileName = request.getParameter("config");
        File file = fileName != null ? new File(userFileFolder, URLDecoder.decode(fileName, StandardCharsets.UTF_8))
                : null;

        if (file != null && file.exists()) {
            // file exists and we only write if the file exists (creating new files this way is prohibited for security
            // reasons
            logger.debug("save config file'{}' requested", file);

            // check is backup folder exists
            File backupFolder = new File(userFileFolder, "config/backup/");
            boolean backup = true;
            if (!backupFolder.exists()) {
                try {
                    backupFolder.mkdir();
                } catch (SecurityException e) {
                    logger.error("Error creating backup directory for CometVisu config files");
                    backup = false;
                }
            }

            if (backup) {
                // Backup existing file
                File backupFile = new File(backupFolder, file.getName() + "-" + System.currentTimeMillis());
                Files.copy(file.toPath(), backupFile.toPath());
            }

            // write data to file
            String data = request.getParameter("data");
            Files.writeString(file.toPath(), data, StandardCharsets.UTF_8);
            resp.success = true;
            resp.message = "File saved";
        }
        response.getWriter().write(marshalJson(resp));
        response.flushBuffer();
    }
```

```diff
@@ -22,8 +22,6 @@
 import java.net.URLDecoder;
-import java.nio.charset.StandardCharsets;
-import java.nio.file.Files;
 import java.text.DateFormat;
@@ -58,6 +56,7 @@
 
+import org.eclipse.jdt.annotation.Nullable;
 import org.openhab.core.OpenHAB;
@@ -103,7 +102,6 @@ public class CometVisuServlet extends HttpServlet {
     private Pattern sitemapPattern = Pattern.compile(".*/visu_config_?(oh_)?([^\\.]+)?\\.xml");
-    private Pattern configStorePattern = Pattern.compile("config/visu_config_oh_([a-z0-9_]+)\\.xml");
 
@@ -112,10 +110,10 @@ public class CometVisuServlet extends HttpServlet {
     protected File userFileFolder;
-    protected String defaultUserDir;
-    protected PHProvider engine;
-    protected ServletContext servletContext;
-    protected ServletConfig config;
+    protected @Nullable String defaultUserDir;
+    protected @Nullable PHProvider engine;
+    protected @Nullable ServletContext servletContext;
+    protected @Nullable ServletConfig config;
 
@@ -146,11 +144,13 @@ public void unsetPHProvider() {
         try {
-            this.engine.createQuercusEngine();
-            this.engine.setIni("include_path", ".:" + rootFolder.getAbsolutePath());
-            if (servletContext != null) {
-                this.engine.init(rootFolder.getAbsolutePath(), defaultUserDir, servletContext);
-                phpEnabled = true;
+            if (this.engine != null) {
+                this.engine.createQuercusEngine();
+                this.engine.setIni("include_path", ".:" + rootFolder.getAbsolutePath());
+                if (servletContext != null) {
+                    this.engine.init(rootFolder.getAbsolutePath(), defaultUserDir, servletContext);
+                    phpEnabled = true;
+                }
             }
@@ -170,10 +170,12 @@ public boolean isPhpEnabled() {
     @Override
-    public final void init(ServletConfig config) throws ServletException {
+    public final void init(@Nullable ServletConfig config) throws ServletException {
         super.init(config);
         this.config = config;
-        servletContext = config.getServletContext();
+        if (config != null) {
+            servletContext = config.getServletContext();
+        }
 
@@ -192,16 +194,10 @@ public final void init(ServletConfig config) throws ServletException {
         File requestedFile = getRequestedFile(req);
-        Matcher match = configStorePattern.matcher(req.getParameter("config"));
-        if (requestedFile.getName().endsWith("save_config.php") && match.find() && req.getParameter("type") != null
-                && req.getParameter("type").equals("xml")) {
-            saveConfig(req, resp);
-        } else {
-            processPhpRequest(requestedFile, req, resp);
-        }
+        processPhpRequest(requestedFile, req, resp);
     }
 
-    private Sitemap getSitemap(String sitemapname) {
+    private @Nullable Sitemap getSitemap(String sitemapname) {
         for (SitemapProvider provider : cometVisuApp.getSitemapProviders()) {
@@ -222,13 +218,14 @@ private Sitemap getSitemap(String sitemapname) {
 
-        String path = req.getPathInfo() != null ? req.getPathInfo() : "/index.html";
+        String path = req.getPathInfo();
+        if (path == null) {
... (truncated)
```

## 58. GHSA-v7gr-mqpj-wwh3:java.lang.security.httpservlet-path-traversal.httpservlet-path-traversal:bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:873

- tags: off-CWE, hunk
- advisory: CometVisu Backend for openHAB affected by SSRF/XSS
- repo: openhab/openhab-webui  commit: 531dabfa8311a50d2e740bf4f2b4f2400e78646c
- entry CWE: ['CWE-918']  finding CWEs: ['CWE-22']
- rule: httpservlet-path-traversal
- finding: bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/servlet/CometVisuServlet.java:873 method saveConfig
- message: Detected a potential path traversal. A malicious actor could control the location of this file, to include going backwards in the directory with '../'. To address this, ensure that user-controlled variables in file paths are sanitized. You may also consider using a utility method such as org.apache.commons.io.FilenameUtils.getName(...) to only retrieve the file name from the path.

```java
public class CometVisuServlet extends HttpServlet {

    private final void saveConfig(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType(MediaType.APPLICATION_JSON);

        class Response {
            public Boolean success = false;
            public String message = "";

            Response() {
            }
        }
        Response resp = new Response();

        String fileName = request.getParameter("config");
        File file = fileName != null ? new File(userFileFolder, URLDecoder.decode(fileName, StandardCharsets.UTF_8))
                : null;

        if (file != null && file.exists()) {
            // file exists and we only write if the file exists (creating new files this way is prohibited for security
            // reasons
            logger.debug("save config file'{}' requested", file);

            // check is backup folder exists
            File backupFolder = new File(userFileFolder, "config/backup/");
            boolean backup = true;
            if (!backupFolder.exists()) {
                try {
                    backupFolder.mkdir();
                } catch (SecurityException e) {
                    logger.error("Error creating backup directory for CometVisu config files");
                    backup = false;
                }
            }

            if (backup) {
                // Backup existing file
                File backupFile = new File(backupFolder, file.getName() + "-" + System.currentTimeMillis());
                Files.copy(file.toPath(), backupFile.toPath());
            }

            // write data to file
            String data = request.getParameter("data");
            Files.writeString(file.toPath(), data, StandardCharsets.UTF_8);
            resp.success = true;
            resp.message = "File saved";
        }
        response.getWriter().write(marshalJson(resp));
        response.flushBuffer();
    }
```

```diff
@@ -22,8 +22,6 @@
 import java.net.URLDecoder;
-import java.nio.charset.StandardCharsets;
-import java.nio.file.Files;
 import java.text.DateFormat;
@@ -58,6 +56,7 @@
 
+import org.eclipse.jdt.annotation.Nullable;
 import org.openhab.core.OpenHAB;
@@ -103,7 +102,6 @@ public class CometVisuServlet extends HttpServlet {
     private Pattern sitemapPattern = Pattern.compile(".*/visu_config_?(oh_)?([^\\.]+)?\\.xml");
-    private Pattern configStorePattern = Pattern.compile("config/visu_config_oh_([a-z0-9_]+)\\.xml");
 
@@ -112,10 +110,10 @@ public class CometVisuServlet extends HttpServlet {
     protected File userFileFolder;
-    protected String defaultUserDir;
-    protected PHProvider engine;
-    protected ServletContext servletContext;
-    protected ServletConfig config;
+    protected @Nullable String defaultUserDir;
+    protected @Nullable PHProvider engine;
+    protected @Nullable ServletContext servletContext;
+    protected @Nullable ServletConfig config;
 
@@ -146,11 +144,13 @@ public void unsetPHProvider() {
         try {
-            this.engine.createQuercusEngine();
-            this.engine.setIni("include_path", ".:" + rootFolder.getAbsolutePath());
-            if (servletContext != null) {
-                this.engine.init(rootFolder.getAbsolutePath(), defaultUserDir, servletContext);
-                phpEnabled = true;
+            if (this.engine != null) {
+                this.engine.createQuercusEngine();
+                this.engine.setIni("include_path", ".:" + rootFolder.getAbsolutePath());
+                if (servletContext != null) {
+                    this.engine.init(rootFolder.getAbsolutePath(), defaultUserDir, servletContext);
+                    phpEnabled = true;
+                }
             }
@@ -170,10 +170,12 @@ public boolean isPhpEnabled() {
     @Override
-    public final void init(ServletConfig config) throws ServletException {
+    public final void init(@Nullable ServletConfig config) throws ServletException {
         super.init(config);
         this.config = config;
-        servletContext = config.getServletContext();
+        if (config != null) {
+            servletContext = config.getServletContext();
+        }
 
@@ -192,16 +194,10 @@ public final void init(ServletConfig config) throws ServletException {
         File requestedFile = getRequestedFile(req);
-        Matcher match = configStorePattern.matcher(req.getParameter("config"));
-        if (requestedFile.getName().endsWith("save_config.php") && match.find() && req.getParameter("type") != null
-                && req.getParameter("type").equals("xml")) {
-            saveConfig(req, resp);
-        } else {
-            processPhpRequest(requestedFile, req, resp);
-        }
+        processPhpRequest(requestedFile, req, resp);
     }
 
-    private Sitemap getSitemap(String sitemapname) {
+    private @Nullable Sitemap getSitemap(String sitemapname) {
         for (SitemapProvider provider : cometVisuApp.getSitemapProviders()) {
@@ -222,13 +218,14 @@ private Sitemap getSitemap(String sitemapname) {
 
-        String path = req.getPathInfo() != null ? req.getPathInfo() : "/index.html";
+        String path = req.getPathInfo();
+        if (path == null) {
... (truncated)
```

## 59. GHSA-vhwv-8897-jm7q:java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing.documentbuilderfactory-disallow-doctype-decl-missing:src/main/java/com/compuware/jenkins/totaltest/TotalTestCTRunner.java:326

- tags: method-only
- advisory: XXE vulnerability in Jenkins Compuware Topaz for Total Test Plugin
- repo: jenkinsci/compuware-topaz-for-total-test-plugin  commit: 9ce24fb63fcdb94290340d2ec53f478635c416ab
- entry CWE: ['CWE-611']  finding CWEs: ['CWE-611']
- rule: documentbuilderfactory-disallow-doctype-decl-missing
- finding: src/main/java/com/compuware/jenkins/totaltest/TotalTestCTRunner.java:326 method getXaScenarioSuiteResultAsDocument
- message: DOCTYPE declarations are enabled for this DocumentBuilderFactory. This is vulnerable to XML external entity attacks. Disable this by setting the feature "http://apache.org/xml/features/disallow-doctype-decl" to true. Alternatively, allow DOCTYPE declarations and only prohibit external entities declarations. This can be done by setting the features "http://xml.org/sax/features/external-general-entities" and "http://xml.org/sax/features/external-parameter-entities" to false.

```java
public class TotalTestCTRunner
{

	private Document getXaScenarioSuiteResultAsDocument(String xml) throws Exception //NOSONAR
	{
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		DocumentBuilder db = dbf.newDocumentBuilder();
		Reader r = new StringReader(xml);
		return db.parse(new InputSource(r));
	}
```

```diff
@@ -323,6 +323,12 @@ else if (extension.compareTo(FILE_EXT_XAUNIT) == 0 ||
 		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
+		dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
+		dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
+		dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
+		dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
+		dbf.setXIncludeAware(false);
+		dbf.setExpandEntityReferences(false);
 		DocumentBuilder db = dbf.newDocumentBuilder();
```

## 60. GHSA-wg5r-wc3x-39vc:java.lang.security.audit.object-deserialization.object-deserialization:openam-core/src/main/java/com/sun/identity/authentication/share/AuthXMLUtils.java:1786

- tags: off-CWE, method-only
- advisory: OpenAM: Unauthenticated Remote Code Execution via Class.forName in AuthXMLUtils.createCustomCallback
- repo: OpenIdentityPlatform/OpenAM  commit: edcf968cad91a78b932dba4ad559ef94cbf35f5a
- entry CWE: ['CWE-94']  finding CWEs: ['CWE-502']
- rule: object-deserialization
- finding: openam-core/src/main/java/com/sun/identity/authentication/share/AuthXMLUtils.java:1786 method getDeSerializedSubject
- message: Found object deserialization using ObjectInputStream. Deserializing entire Java objects is dangerous because malicious actors can create Java object streams with unintended consequences. Ensure that the objects being deserialized are not user-controlled. If this must be done, consider using HMACs to sign the data stream to make sure it is not tampered with, or consider only transmitting object fields and populating a new object.

```java
public class AuthXMLUtils {

    public static Subject getDeSerializedSubject(String subjectSerialized)
        throws Exception {
        
        // decrypt and then decode
        String decStr = (String) AccessController.doPrivileged(
        new DecodeAction(subjectSerialized));
        byte[] sSerialized = Base64.decode(decStr);
        
        if (sSerialized == null) return null;
        byte byteDecrypted[];
        ByteArrayInputStream byteIn;
        ObjectInputStream objInStream = null;
        Object tempObject = null;
        try{
            byteDecrypted = sSerialized;
            //convert byte to object using streams
            byteIn = new ByteArrayInputStream(byteDecrypted);
            objInStream  = new ObjectInputStream(byteIn);
            tempObject = objInStream.readObject();
        }catch(Exception e){
            debug.message("Exception Message in decrypt: " , e);
        }
        if (tempObject == null) return null;
        
        Subject subjectObj = (Subject) tempObject;
        
        if (debug.messageEnabled()) {
            debug.message("returning temp" + subjectObj);
        }
        return subjectObj;
    }
```

```diff
@@ -46,9 +46,11 @@
 import java.io.IOException;
+import java.io.ObjectInputFilter;
 import java.io.ObjectInputStream;
 import java.security.AccessController;
+import java.security.Principal;
 import java.security.cert.CertificateEncodingException;
@@ -1609,7 +1611,19 @@ static DSAMECallbackInterface createCustomCallback(
                 if ((className != null) && (className.length() != 0)) {
-                    Class xmlClass = Class.forName(className);
+                    // The class name is read from attacker-controllable XML on the
+                    // unauthenticated /authservice endpoint. Load the class without
+                    // running its static initializers and verify it implements
+                    // DSAMECallbackInterface BEFORE instantiating it; otherwise an
+                    // arbitrary class could be instantiated, leading to remote code
+                    // execution (GHSA-wg5r-wc3x-39vc).
+                    Class xmlClass = Class.forName(className, false,
+                        AuthXMLUtils.class.getClassLoader());
+                    if (!DSAMECallbackInterface.class.isAssignableFrom(xmlClass)) {
+                        debug.error("createCustomCallback : class " + className
+                            + " is not a DSAMECallbackInterface implementation");
+                        return null;
+                    }
                     callback = (DSAMECallbackInterface) xmlClass.newInstance();
@@ -1760,6 +1774,44 @@ public static String getSerializedSubject(Subject subject) {
     
+    // Hardened deserialization filter for the encrypted <Subject> value received
+    // from the auth server. The value is Java-serialized, so without a class
+    // allowlist a forged or relayed response could trigger gadget-chain code
+    // execution in the AuthContext client. A legitimate javax.security.auth.Subject
+    // graph only contains the Subject itself, JDK collections/scalars and
+    // java.security.Principal implementations (GHSA-wg5r-wc3x-39vc, related
+    // deserialization hardening).
+    private static final ObjectInputFilter SUBJECT_DESERIALISATION_FILTER =
+        AuthXMLUtils::filterSubjectClass;
+
+    private static ObjectInputFilter.Status filterSubjectClass(
+            ObjectInputFilter.FilterInfo info) {
+        // Reject oversized or deeply nested graphs before resolving any class.
+        if (info.depth() > 20L || info.references() > 1000L
+                || info.arrayLength() > 10000L) {
+            return ObjectInputFilter.Status.REJECTED;
+        }
+        Class<?> clazz = info.serialClass();
+        if (clazz == null) {
+            return ObjectInputFilter.Status.UNDECIDED;
+        }
+        while (clazz.isArray()) {
+            clazz = clazz.getComponentType();
+        }
+        if (clazz.isPrimitive() || Principal.class.isAssignableFrom(clazz)) {
+            return ObjectInputFilter.Status.ALLOWED;
+        }
+        String name = clazz.getName();
+        if (name.startsWith("java.lang.") || name.startsWith("java.util.")
+                || name.startsWith("java.security.")
+                || name.startsWith("javax.security.")) {
+            return ObjectInputFilter.Status.ALLOWED;
+        }
+        debug.warning("getDeSerializedSubject : rejected class " + name
+            + " during Subject deserialization");
+        return ObjectInputFilter.Status.REJECTED;
+    }
+
     /**
@@ -1784,6 +1836,7 @@ public static Subject getDeSerializedSubject(String subjectSerialized)
             objInStream  = new ObjectInputStream(byteIn);
+            objInStream.setObjectInputFilter(SUBJECT_DESERIALISATION_FILTER);
             tempObject = objInStream.readObject();
```

## 61. GHSA-x832-fpvj-r5ph:java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing.documentbuilderfactory-disallow-doctype-decl-missing:library/src/main/java/org/mustangproject/ZUGFeRD/ZUGFeRDVisualizer.java:104

- tags: method-only
- advisory: Mustangproject allows exfiltrating files via XXE attacks
- repo: ZUGFeRD/mustangproject  commit: 6461dad8d3d7876547155dacbd28b458f1eb2e0b
- entry CWE: ['CWE-611']  finding CWEs: ['CWE-611']
- rule: documentbuilderfactory-disallow-doctype-decl-missing
- finding: library/src/main/java/org/mustangproject/ZUGFeRD/ZUGFeRDVisualizer.java:104 method findOutStandardFromRootNode
- message: DOCTYPE declarations are enabled for this DocumentBuilderFactory. This is vulnerable to XML external entity attacks. Disable this by setting the feature "http://apache.org/xml/features/disallow-doctype-decl" to true. Alternatively, allow DOCTYPE declarations and only prohibit external entities declarations. This can be done by setting the features "http://xml.org/sax/features/external-general-entities" and "http://xml.org/sax/features/external-parameter-entities" to false.

```java
public class ZUGFeRDVisualizer {

	private EStandard findOutStandardFromRootNode(InputStream fis) {

		String zf1Signature = "CrossIndustryDocument";
		String zf2Signature = "CrossIndustryInvoice";
		String ublSignature = "Invoice";
		String ublCreditNoteSignature = "CreditNote";
		String cioSignature = "SCRDMCCBDACIOMessageStructure";

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		try {
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document doc = db.parse(new InputSource(fis));
			Element root = doc.getDocumentElement();
			if (root.getLocalName().equals(zf1Signature)) {
				return EStandard.zugferd;
			} else if (root.getLocalName().equals(zf2Signature)) {
				return EStandard.facturx;
			} else if (root.getLocalName().equals(ublSignature)) {
				return EStandard.ubl;
			} else if (root.getLocalName().equals(ublCreditNoteSignature)) {
				return EStandard.ubl_creditnote;
			} else if (root.getLocalName().equals(cioSignature)) {
				return EStandard.orderx;
			}
		} catch (Exception e) {
			LOGGER.error("Failed to recognize standard", e);
		}
		return null;
	}
```

```diff
@@ -21,6 +21,8 @@
 import com.helger.commons.io.stream.StreamHelper;
+import javax.xml.XMLConstants;
+import javax.xml.parsers.ParserConfigurationException;
 import org.apache.commons.io.IOUtils;
@@ -90,7 +92,8 @@ public ZUGFeRDVisualizer() {
 	 */
-	private EStandard findOutStandardFromRootNode(InputStream fis) {
+	private EStandard findOutStandardFromRootNode(InputStream fis)
+		throws ParserConfigurationException {
 
@@ -100,6 +103,11 @@ private EStandard findOutStandardFromRootNode(InputStream fis) {
 		dbf.setNamespaceAware(true);
+		dbf.setExpandEntityReferences(false);
+		dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
+		dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
+		dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
+		dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
 		try {
@@ -121,12 +129,14 @@ private EStandard findOutStandardFromRootNode(InputStream fis) {
 
-	public String visualize(String xmlFilename, Language lang) throws IOException, TransformerException {
+	public String visualize(String xmlFilename, Language lang)
+		throws IOException, TransformerException, ParserConfigurationException {
 		FileInputStream fis = new FileInputStream(xmlFilename);
 
-	public String visualize(InputStream inputXml, Language lang) throws IOException, TransformerException {
+	public String visualize(InputStream inputXml, Language lang)
+		throws IOException, TransformerException, ParserConfigurationException {
 		initTemplates(lang);
@@ -211,7 +221,7 @@ private void initTemplates(Language lang) throws TransformerConfigurationExcepti
 	protected String toFOP(String xmlFilename)
-		throws IOException, TransformerException {
+		throws IOException, TransformerException, ParserConfigurationException {
 
@@ -264,7 +274,7 @@ out from git with arbitrary options (which may include CSRF changes)
 			fopInput = this.toFOP(XMLinputFile.getAbsolutePath());
-		} catch (TransformerException | IOException e) {
+		} catch (TransformerException | IOException | ParserConfigurationException e) {
 			LOGGER.error("Failed to apply FOP", e);
@@ -291,7 +301,7 @@ out from git with arbitrary options (which may include CSRF changes)
 			fopInput = toFOP(fis, theStandard);
-		} catch (TransformerException | IOException e) {
+		} catch (TransformerException | IOException | ParserConfigurationException e) {
 			LOGGER.error("Failed to apply FOP", e);
```

## 62. GHSA-x832-fpvj-r5ph:java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing.documentbuilderfactory-disallow-doctype-decl-missing:validator/src/main/java/org/mustangproject/validator/XMLValidator.java:155

- tags: method-only, on-CWE-sample
- advisory: Mustangproject allows exfiltrating files via XXE attacks
- repo: ZUGFeRD/mustangproject  commit: 6461dad8d3d7876547155dacbd28b458f1eb2e0b
- entry CWE: ['CWE-611']  finding CWEs: ['CWE-611']
- rule: documentbuilderfactory-disallow-doctype-decl-missing
- finding: validator/src/main/java/org/mustangproject/validator/XMLValidator.java:155 method validate
- message: DOCTYPE declarations are enabled for this DocumentBuilderFactory. This is vulnerable to XML external entity attacks. Disable this by setting the feature "http://apache.org/xml/features/disallow-doctype-decl" to true. Alternatively, allow DOCTYPE declarations and only prohibit external entities declarations. This can be done by setting the features "http://xml.org/sax/features/external-general-entities" and "http://xml.org/sax/features/external-parameter-entities" to false.

```java
public class XMLValidator extends Validator {

	public void validate() throws IrrecoverableValidationError {
		final long startXMLTime = Calendar.getInstance().getTimeInMillis();
		firedRules = 0;
		failedRules = 0;


		if (zfXML.isEmpty()) {
			final ValidationResultItem res = new ValidationResultItem(ESeverity.exception,
				"XML data not found in " + filename
					+ ": did you specify a pdf or xml file and does the xml file contain an embedded XML file?")
				.setSection(3);
			context.addResultItem(res);

		} else {

			// final ISchematronResource aResSCH =
			// SchematronResourceSCH.fromFile (new File("ZUGFeRD_1p0.scmt"));
			// ... DOES work but is highly deprecated (and rightly so) because
			// it takes 30-40min,

			try {
				ESeverity XrechnungSeverity = ESeverity.notice;
				/***
				 * private static final String VALID_SCHEMATRON = "test-sch/valid01.sch";
				 * private static final String VALID_XMLINSTANCE = "test-xml/valid01.xml";
				 *
				 * @Test public void testWriteValid () throws Exception { final Document aDoc =
				 *       SchematronResourceSCH.fromClassPath (VALID_SCHEMATRON)
				 *       .applySchematronValidation (new ClassPathResource (VALID_XMLINSTANCE));
				 *
				 */

				final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
				dbf.setNamespaceAware(true); // otherwise we can not act namespace independently, i.e. use
				// document.getElementsByTagNameNS("*",...

				final DocumentBuilder db = dbf.newDocumentBuilder();
				final InputSource is = new InputSource(new StringReader(zfXML));
				final Document doc = db.parse(is);

				final Element root = doc.getDocumentElement();

				final NodeList ndList;

				// rootNode = document.getDocumentElement();
				// ApplicableSupplyChainTradeSettlement

				// Create XPathFactory object
				final XPathFactory xpathFactory = XPathFactory.newInstance();

				// Create XPath object
				final XPath xpath = xpathFactory.newXPath();
				final XPathExpression expr = xpath.compile(
					"(//*[local-name()=\"GuidelineSpecifiedDocumentContextParameter\"]/*[local-name()=\"ID\"])/text()|//*[local-name()=\"CustomizationID\"]/text()");
				// evaluate expression result on XML document
				ndList = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);

				for (int bookingIndex = 0; bookingIndex < ndList.getLength(); bookingIndex++) {
					final Node booking = ndList.item(bookingIndex);
					// if there is a attribute in the tag number:value
					// urn:ferd:CrossIndustryDocument:invoice:1p0:extended
					// setForeignReference(booking.getTextContent());

					context.setProfile(booking.getNodeValue());
				}
				boolean isOrderX = false;
				boolean isDespatchAdvice = false;
				boolean isMiniumum = false;
				boolean isBasic = false;
				boolean isBasicWithoutLines = false;
				boolean isEN16931 = false;
				boolean isExtended = false;
				boolean isXRechnung = false;
				String currentZFVersionDir = "ZF_232";
				int mainSchematronSectionErrorTypeCode = 4;
				String xsltFilename = null;
				// urn:ferd:CrossIndustryDocument:invoice:1p0:extended,
				// urn:ferd:CrossIndustryDocument:invoice:1p0:comfort,
				// urn:ferd:CrossIndustryDocument:invoice:1p0:basic,

				// urn:cen.eu:en16931:2017
				// urn:cen.eu:en16931:2017:compliant:factur-x.eu:1p0:basic
				if (root.getLocalName().equalsIgnoreCase("SCRDMCCBDACIOMessageStructure")) {
					context.setGeneration("1");
					isOrderX = true;
					isBasic = context.getProfile().contains("basic");
					isEN16931 = context.getProfile().contains("comfort");
					isExtended = context.getProfile().contains("extended");
... (truncated)
```

```diff
@@ -10,6 +10,7 @@
 
+import javax.xml.XMLConstants;
 import javax.xml.parsers.DocumentBuilder;
@@ -151,6 +152,11 @@ public void validate() throws IrrecoverableValidationError {
 				// document.getElementsByTagNameNS("*",...
+				dbf.setExpandEntityReferences(false);
+				dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
+				dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
+				dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
+				dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
 
```

## 63. GHSA-x832-fpvj-r5ph:java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing.documentbuilderfactory-disallow-doctype-decl-missing:validator/src/main/java/org/mustangproject/validator/ZUGFeRDValidator.java:145

- tags: method-only
- advisory: Mustangproject allows exfiltrating files via XXE attacks
- repo: ZUGFeRD/mustangproject  commit: 6461dad8d3d7876547155dacbd28b458f1eb2e0b
- entry CWE: ['CWE-611']  finding CWEs: ['CWE-611']
- rule: documentbuilderfactory-disallow-doctype-decl-missing
- finding: validator/src/main/java/org/mustangproject/validator/ZUGFeRDValidator.java:145 method internalValidate
- message: DOCTYPE declarations are enabled for this DocumentBuilderFactory. This is vulnerable to XML external entity attacks. Disable this by setting the feature "http://apache.org/xml/features/disallow-doctype-decl" to true. Alternatively, allow DOCTYPE declarations and only prohibit external entities declarations. This can be done by setting the features "http://xml.org/sax/features/external-general-entities" and "http://xml.org/sax/features/external-parameter-entities" to false.

```java
public class ZUGFeRDValidator {

	private String internalValidate(String contextFilename, InputStream inputStream, long inputLength) {
		context.clear();
		StringBuilder finalStringResult = new StringBuilder();
		SimpleDateFormat isoDF = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		Date date = new Date();
		startTime = Calendar.getInstance().getTimeInMillis();
		context.setFilename(contextFilename);// fallback to provided name
		finalStringResult.append("<validation filename='").append(contextFilename).append("' datetime='").append(isoDF.format(date)).append("'>");

		boolean isPDF = false;
		byte[] content = null;
		try {

			if (contextFilename == null || contextFilename.isEmpty()) {
				optionsRecognized = false;
				context.addResultItem(new ValidationResultItem(ESeverity.fatal, "Filename not specified").setSection(10)
					.setPart(EPart.pdf));
			}

			PDFValidator pdfv = new PDFValidator(context);
			if (inputStream == null) {
				context.addResultItem(
					new ValidationResultItem(ESeverity.fatal, "File not found").setSection(1).setPart(EPart.pdf));
			} else if (inputLength < 32) {
				// with less than 32 bytes it can not even be a proper XML file
				// Except it is "<?xml version='1.0'?><xml/>" LOL
				context.addResultItem(
					new ValidationResultItem(ESeverity.fatal, "File too small").setSection(5).setPart(EPart.pdf));
			} else if (inputLength >= Integer.MAX_VALUE) {
				// Byte arrays are limited to 2GB in Java
				context.addResultItem(
					new ValidationResultItem(ESeverity.fatal, "File too big").setSection(5).setPart(EPart.pdf));
			} else {
				content = IOUtils.toByteArray(inputStream);
				XMLValidator xv = new XMLValidator(context);
				if (disableNotices) {
					xv.disableNotices();
				}
				isPDF = ByteArraySearcher.startsWith(content, new byte[]{'%', 'P', 'D', 'F'});
				if (isPDF) {
					// Avoid reading again from file
					pdfv.setFilenameAndContents(contextFilename, content);

					optionsRecognized = true;
					finalStringResult.append("<pdf>");
					try {
						pdfv.validate();

						sha1Checksum = calcSHA1(content);

						// Validate PDF

						getPdfValidationResults(finalStringResult, pdfv, xv);
					} catch (IrrecoverableValidationError irx) {
						LOGGER.info(irx.getMessage());
					}

					finalStringResult.append("</pdf>\n");

					context.clearCustomXML();
				} else {
					boolean isXML = false;
					String xmlAsString = null;
					try {
						DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
						DocumentBuilder db = dbf.newDocumentBuilder();

						content = XMLTools.removeBOM(content);
						xmlAsString = new String(content, StandardCharsets.UTF_8);
						InputSource is = new InputSource(new StringReader(xmlAsString));
						Document doc = db.parse(is);

						Element root = doc.getDocumentElement();
						isXML = true;//no exception so far

					} catch (Exception ex) {
						// probably no xml file, sth like SAXParseException content not allowed in prolog
						// ignore isXML is already false
						// in the tests, this may error-out anyway
						LOGGER.info("No XML part provided");
					}
					if (isXML) {
						pdfValidity = true;
						optionsRecognized = true;
						xv.setStringContent(xmlAsString);
						xv.setAutoload(false);
						xv.setFilename(contextFilename);
						sha1Checksum = calcSHA1(content);
... (truncated)
```

```diff
@@ -17,6 +17,7 @@
 
+import javax.xml.XMLConstants;
 import javax.xml.parsers.DocumentBuilder;
@@ -142,6 +143,12 @@ private String internalValidate(String contextFilename, InputStream inputStream,
 						DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
+						dbf.setNamespaceAware(true);
+						dbf.setExpandEntityReferences(false);
+						dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
+						dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
+						dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
+						dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
 						DocumentBuilder db = dbf.newDocumentBuilder();
```

## 64. GHSA-xrrw-9j78-hpf3:java.lang.security.audit.crypto.use-of-sha1.use-of-sha1:src/main/java/htmlpublisher/HtmlPublisher.java:118

- tags: off-CWE, method-only
- advisory: Jenkins HTML Publisher Plugin Stored XSS vulnerability
- repo: jenkinsci/htmlpublisher-plugin  commit: c0eed940e65ea90f9b5ba21aa3d953546d5cd8ad
- entry CWE: ['CWE-79']  finding CWEs: ['CWE-328']
- rule: use-of-sha1
- finding: src/main/java/htmlpublisher/HtmlPublisher.java:118 method writeFile
- message: Detected SHA1 hash algorithm which is considered insecure. SHA1 is not collision resistant and is therefore not suitable as a cryptographic signature. Instead, use PBKDF2 for password hashing or SHA256 or SHA512 for other hash function applications.

```java
public class HtmlPublisher extends Recorder {

    private static String writeFile(List<String> lines, File path) throws IOException, NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        //TODO: consider using UTF-8
        try (FileOutputStream fos = new FileOutputStream(path);
                OutputStreamWriter osw = new OutputStreamWriter(fos, Charset.defaultCharset());
                BufferedWriter bw = new BufferedWriter(osw)) {
            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i) + "\n";
                bw.write(line);
                sha1.update(line.getBytes(StandardCharsets.UTF_8));
            }
        }

        return Util.toHexString(sha1.digest());
    }
```

```diff
@@ -81,6 +81,8 @@
 
+import static hudson.Functions.htmlAttributeEscape;
+
 
@@ -130,7 +132,7 @@ private static String writeFile(List<String> lines, File path) throws IOExceptio
 
-    public List<String> readFile(String filePath) throws 
+    public List<String> readFile(String filePath) throws
             java.io.IOException {
@@ -302,7 +304,7 @@ public static boolean publishReports(Run<?, ?> build, FilePath workspace, TaskLi
                 report = report.replace("\\", "/");
-	
+
                 // Ignore blank report names caused by trailing or double commas.
@@ -318,13 +320,13 @@ public static boolean publishReports(Run<?, ?> build, FilePath workspace, TaskLi
                 }
-                String tabItem = "<li id=\"" + tabNo + "\" class=\"unselected\" onclick=\"updateBody('" + tabNo + "');\" value=\"" + report + "\">" + getTitle(reportFile, titles, j) + "</li>";
+                String tabItem = "<li id=\"" + tabNo + "\" class=\"unselected\" onclick=\"updateBody('" + tabNo + "');\" value=\"" + htmlAttributeEscape(report) + "\">" + htmlAttributeEscape(getTitle(reportFile, titles, j)) + "</li>";
                 reportLines.add(tabItem);
             Job job = build.getParent();
-            reportLines.add("<script type=\"text/javascript\">document.getElementById(\"hudson_link\").innerHTML=\"Back to " + job.getName() + "\";</script>");
+            reportLines.add("<script type=\"text/javascript\">document.getElementById(\"hudson_link\").innerHTML=\"Back to " + htmlAttributeEscape(job.getName()) + "\";</script>");
             // If the URL isn't configured in Hudson, the best we can do is attempt to go Back.
```
