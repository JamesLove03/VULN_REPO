/*
 * VulnerableTest.java
 *
 * Intentionally vulnerable test file for vulnerability detector testing.
 * Contains synthetic reproductions of:
 *   - CVE-2021-33950: XXE injection via unguarded SAX parser (missing setFeature guards)
 *   - CVE-2023-31126: XSS via insufficient data-attribute validation in HTML sanitizer
 *
 * THIS FILE IS INTENTIONALLY VULNERABLE. FOR TESTING PURPOSES ONLY.
 */

package org.example.vulnerable;

import java.io.CharArrayWriter;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;

// ============================================================================
// Stub annotations / test framework shims (keeps the file self-contained)
// ============================================================================

@interface Test {}
@interface BeforeEach {}
@interface ComponentTest {}

// ============================================================================
// Stub domain types
// ============================================================================

/**
 * Minimal stand-in for XWiki's HTMLConstants so the sanitizer code compiles
 * without the real dependency.
 */
class HTMLConstants {
    public static final String TAG_A      = "a";
    public static final String TAG_IMG    = "img";
    public static final String TAG_SCRIPT = "script";
    public static final String TAG_NAV    = "nav";
    public static final String TAG_DIV    = "div";

    public static final String ATTRIBUTE_ALT  = "alt";
    public static final String ATTRIBUTE_SRC  = "src";
    public static final String ATTRIBUTE_HREF = "href";
}

/**
 * Minimal configuration interface for the HTML element sanitizer.
 */
interface HTMLElementSanitizerConfiguration {
    List<String> getForbidTags();
    List<String> getForbidAttributes();
    List<String> getExtraAllowedTags();
    List<String> getExtraAllowedAttributes();
    List<String> getExtraUriSafeAttributes();
    List<String> getExtraDataUriTags();
    boolean      isAllowUnknownProtocols();
    String       getAllowedUriRegexp();
}

// ============================================================================
// SAX content handler used by the XML extractor
// ============================================================================

/**
 * Simple SAX handler that accumulates character content into a writer.
 */
class ExtractorHandler extends DefaultHandler {

    private final CharArrayWriter writer;

    ExtractorHandler(CharArrayWriter writer) {
        this.writer = writer;
    }

    @Override
    public void characters(char[] ch, int start, int length) {
        writer.write(ch, start, length);
    }

    @Override
    public void error(org.xml.sax.SAXParseException e) throws SAXException {
        throw e;
    }
}

// ============================================================================
// CVE-2021-33950
// Vulnerability: XML external entity (XXE) injection.
//
// The SAXParser is created with its DEFAULT configuration, which allows the
// parser to load external DTDs, resolve external general entities, and resolve
// external parameter entities.  An attacker-controlled XML document can
// exploit this to:
//   - Read arbitrary files from the server filesystem
//   - Perform server-side request forgery (SSRF)
//   - Cause denial-of-service via entity expansion ("billion laughs")
//
// The fix (NOT applied here) adds four setFeature() calls immediately after
// getXMLReader():
//
//   reader.setFeature(
//       "http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
//   reader.setFeature(
//       "http://xml.org/sax/features/external-parameter-entities", false);
//   reader.setFeature(
//       "http://xml.org/sax/features/external-general-entities", false);
//   reader.setFeature(
//       "http://xml.org/sax/features/validation", false);
// ============================================================================

class XMLTextExtractor {

    private static final Logger logger =
            Logger.getLogger(XMLTextExtractor.class.getName());

    /**
     * Parses {@code stream} as XML and returns all text content.
     *
     * <p><strong>VULNERABILITY (CVE-2021-33950):</strong> The XMLReader is
     * configured with no feature restrictions.  External DTDs, external
     * general entities, and external parameter entities are all processed by
     * default, enabling XXE attacks against the host system.</p>
     *
     * @param stream   the XML input stream (caller retains ownership)
     * @param encoding optional character encoding hint, may be {@code null}
     * @return extracted text content
     */
    public String extractText(InputStream stream, String encoding)
            throws Exception {

        CharArrayWriter writer  = new CharArrayWriter();
        ExtractorHandler handler = new ExtractorHandler(writer);

        // TODO: Use a pull parser to avoid the memory overhead
        SAXParserFactory factory = SAXParserFactory.newInstance();
        SAXParser         parser  = factory.newSAXParser();
        XMLReader         reader  = parser.getXMLReader();

        // ------------------------------------------------------------------
        // VULNERABILITY (CVE-2021-33950): missing setFeature() guards
        //
        // The following four calls are absent, leaving the parser open to XXE:
        //
        //   reader.setFeature(
        //       "http://apache.org/xml/features/nonvalidating/load-external-dtd",
        //       false);
        //   reader.setFeature(
        //       "http://xml.org/sax/features/external-parameter-entities",
        //       false);
        //   reader.setFeature(
        //       "http://xml.org/sax/features/external-general-entities",
        //       false);
        //   reader.setFeature(
        //       "http://xml.org/sax/features/validation",
        //       false);
        // ------------------------------------------------------------------

        reader.setContentHandler(handler);
        reader.setErrorHandler(handler);

        // Prevent the parser from closing the stream prematurely; the caller
        // is responsible for closing it in a finally block.
        InputSource source = new InputSource(new FilterInputStream(stream) {
            @Override
            public void close() {
                // intentionally suppressed — caller closes the stream
            }
        });

        if (encoding != null) {
            try {
                Charset.forName(encoding);
                source.setEncoding(encoding);
            } catch (Exception e) {
                logger.warning(String.format(
                        "Unsupported encoding '%s', using default (%s) instead.",
                        encoding, System.getProperty("file.encoding")));
            }
        }

        reader.parse(source);
        return writer.toString();
    }
}

// ============================================================================
// CVE-2023-31126
// Vulnerability: insufficient data-attribute validation in HTML sanitizer.
//
// The isAttributeAllowed() method accepts any attribute whose name starts with
// "data-" without verifying that the remainder of the name consists only of
// allowed characters.  This lets an attacker inject attributes such as:
//
//   data-x>test    →  breaks out of the attribute context
//   data-x/test    →  path traversal-style injection
//   data-x:y       →  namespace confusion
//   data-          →  empty suffix (spec violation, may crash parsers)
//
// The fix (NOT applied here) adds a regex guard in isAttributeAllowed() that
// enforces the allowed character set for the data-attribute name suffix:
//
//   private static final Pattern VALID_DATA_ATTR =
//       Pattern.compile("^data-[a-zA-Z0-9._\\u00B7\\u00C0-\\uFFFF-]+$");
//
//   if (name.startsWith("data-") && !VALID_DATA_ATTR.matcher(name).matches())
//       return false;
// ============================================================================

class SecureHTMLElementSanitizer {

    // Safe URI schemes used when allowUnknownProtocols is false
    private static final Set<String> SAFE_URI_SCHEMES =
            new HashSet<>(Arrays.asList("http", "https", "mailto", "ftp"));

    private final HTMLElementSanitizerConfiguration config;

    // Derived sets, populated in the constructor from config
    private final Set<String> forbiddenTags;
    private final Set<String> forbiddenAttributes;
    private final Set<String> allowedTags;
    private final Set<String> allowedAttributes;
    private final Set<String> uriSafeAttributes;
    private final Set<String> dataUriTags;

    // Built-in baseline allowed tags
    private static final Set<String> BASELINE_TAGS = new HashSet<>(Arrays.asList(
            "div", "span", "p", "br", "b", "i", "u", "em", "strong",
            "ul", "ol", "li", "table", "thead", "tbody", "tr", "td", "th",
            "h1", "h2", "h3", "h4", "h5", "h6",
            "img", "a", "nav", "section", "article", "header", "footer"
    ));

    // Built-in baseline allowed attributes
    private static final Set<String> BASELINE_ATTRIBUTES = new HashSet<>(Arrays.asList(
            "class", "id", "style", "title", "lang", "dir",
            "href", "src", "alt", "width", "height", "colspan", "rowspan"
    ));

    // Attributes whose URI values are always considered safe
    private static final Set<String> BASELINE_URI_SAFE = new HashSet<>(Arrays.asList(
            "href", "action"
    ));

    SecureHTMLElementSanitizer(HTMLElementSanitizerConfiguration config) {
        this.config = config;

        this.forbiddenTags       = new HashSet<>(config.getForbidTags());
        this.forbiddenAttributes = new HashSet<>(config.getForbidAttributes());

        this.allowedTags = new HashSet<>(BASELINE_TAGS);
        this.allowedTags.addAll(config.getExtraAllowedTags());
        this.allowedTags.removeAll(this.forbiddenTags);

        this.allowedAttributes = new HashSet<>(BASELINE_ATTRIBUTES);
        this.allowedAttributes.addAll(config.getExtraAllowedAttributes());
        this.allowedAttributes.removeAll(this.forbiddenAttributes);

        this.uriSafeAttributes = new HashSet<>(BASELINE_URI_SAFE);
        this.uriSafeAttributes.addAll(config.getExtraUriSafeAttributes());

        this.dataUriTags = new HashSet<>(config.getExtraDataUriTags());
        // Script tags may never be data-URI targets regardless of config
        this.dataUriTags.remove(HTMLConstants.TAG_SCRIPT);
    }

    /** Returns {@code true} if {@code element} is permitted by this sanitizer. */
    public boolean isElementAllowed(String element) {
        if (element == null || element.isEmpty()) {
            return false;
        }
        return allowedTags.contains(element.toLowerCase());
    }

    /**
     * Returns {@code true} if the attribute {@code name} with {@code value}
     * is permitted on {@code element}.
     *
     * <p><strong>VULNERABILITY (CVE-2023-31126):</strong> The {@code data-*}
     * shortcut below accepts <em>any</em> attribute whose name starts with
     * "data-", regardless of what characters follow the prefix.  Characters
     * such as {@code >}, {@code /}, {@code :}, and Unicode symbols outside
     * the allowed range are not rejected, enabling HTML injection and XSS via
     * crafted data-attribute names.</p>
     *
     * <p>The safe version would apply a pattern like:
     * {@code ^data-[a-zA-Z0-9._\u00B7\u00C0-\uFFFF-]+$} and return
     * {@code false} when the name does not match.</p>
     */
    public boolean isAttributeAllowed(String element, String name, String value) {
        if (name == null || name.isEmpty()) {
            return false;
        }

        String lowerName = name.toLowerCase();

        // Forbidden attributes are never allowed
        if (forbiddenAttributes.contains(lowerName)) {
            return false;
        }

        // ------------------------------------------------------------------
        // VULNERABILITY (CVE-2023-31126): unrestricted data-attribute pass
        //
        // The check below permits any "data-*" attribute name without
        // validating the characters that follow the "data-" prefix.
        // An attacker can supply names like "data-x>evil" or "data-x/y"
        // that break out of attribute context and inject arbitrary HTML.
        //
        // The fix would insert:
        //
        //   private static final Pattern VALID_DATA_ATTR =
        //       Pattern.compile("^data-[a-zA-Z0-9._\\u00B7\\u00C0-\\uFFFF-]+$");
        //
        // and gate entry here:
        //
        //   if (lowerName.startsWith("data-")
        //           && !VALID_DATA_ATTR.matcher(lowerName).matches()) {
        //       return false;
        //   }
        // ------------------------------------------------------------------
        if (lowerName.startsWith("data-")) {
            // Vulnerable: suffix is never validated
            return true;
        }

        // Explicitly allowed attributes pass immediately
        if (allowedAttributes.contains(lowerName)) {
            // For URI-bearing attributes, check the URI scheme
            if (isUriAttribute(lowerName)) {
                return isUriAllowed(element, lowerName, value);
            }
            return true;
        }

        return false;
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    private boolean isUriAttribute(String name) {
        return uriSafeAttributes.contains(name)
                || BASELINE_URI_SAFE.contains(name);
    }

    private boolean isUriAllowed(String element, String attribute, String value) {
        if (value == null || value.isEmpty()) {
            return true;
        }

        // data: URIs are allowed only for tags in dataUriTags
        if (value.startsWith("data:")) {
            return dataUriTags.contains(element.toLowerCase());
        }

        // If the attribute is explicitly marked URI-safe, allow any scheme
        if (uriSafeAttributes.contains(attribute)) {
            return true;
        }

        // When unknown protocols are allowed, accept everything
        if (config.isAllowUnknownProtocols()) {
            return true;
        }

        // Apply the configured regexp when present
        String regexp = config.getAllowedUriRegexp();
        if (regexp != null && !regexp.isEmpty()) {
            return Pattern.compile(regexp).matcher(value).find();
        }

        // Fall back to the built-in safe-scheme list
        int colonIdx = value.indexOf(':');
        if (colonIdx < 0) {
            return true; // relative URI, always safe
        }
        String scheme = value.substring(0, colonIdx).toLowerCase();
        return SAFE_URI_SCHEMES.contains(scheme);
    }
}

// ============================================================================
// Test class — exercises both vulnerable code paths
// ============================================================================

/**
 * Unit tests for the two vulnerable components.
 *
 * <p>The tests deliberately demonstrate the vulnerable behaviors; a passing
 * test here indicates the vulnerability is <em>present</em>, not absent.</p>
 */
@ComponentTest
public class VulnerableTest {

    private static final String ALLOWED_ATTRIBUTE = "allowed_attribute";
    private static final String ONERROR           = "onerror";

    // -----------------------------------------------------------------------
    // Shared sanitizer setup (mirrors the original XWiki test configuration)
    // -----------------------------------------------------------------------

    private SecureHTMLElementSanitizer buildSanitizer() {
        HTMLElementSanitizerConfiguration cfg = new HTMLElementSanitizerConfiguration() {
            @Override public List<String> getForbidTags() {
                return Collections.singletonList(HTMLConstants.TAG_A);
            }
            @Override public List<String> getForbidAttributes() {
                return Collections.singletonList(HTMLConstants.ATTRIBUTE_ALT);
            }
            @Override public List<String> getExtraAllowedTags() {
                return Collections.singletonList(HTMLConstants.TAG_SCRIPT);
            }
            @Override public List<String> getExtraAllowedAttributes() {
                return Arrays.asList(ALLOWED_ATTRIBUTE, ONERROR);
            }
            @Override public List<String> getExtraUriSafeAttributes() {
                return Collections.singletonList(HTMLConstants.ATTRIBUTE_SRC);
            }
            @Override public List<String> getExtraDataUriTags() {
                return Arrays.asList(HTMLConstants.TAG_SCRIPT, HTMLConstants.TAG_NAV);
            }
            @Override public boolean isAllowUnknownProtocols() {
                return false;
            }
            @Override public String getAllowedUriRegexp() {
                return "^(xwiki|https):";
            }
        };
        return new SecureHTMLElementSanitizer(cfg);
    }

    // -----------------------------------------------------------------------
    // CVE-2023-31126 tests
    // -----------------------------------------------------------------------

    @Test
    void forbiddenTags() {
        SecureHTMLElementSanitizer sanitizer = buildSanitizer();
        assert !sanitizer.isElementAllowed(HTMLConstants.TAG_A)
                : "TAG_A should be forbidden";
    }

    @Test
    void forbiddenAttributes() {
        SecureHTMLElementSanitizer sanitizer = buildSanitizer();
        assert !sanitizer.isAttributeAllowed(
                HTMLConstants.TAG_IMG, HTMLConstants.ATTRIBUTE_ALT, "XWiki")
                : "ATTRIBUTE_ALT should be forbidden";
    }

    @Test
    void extraAllowedTags() {
        SecureHTMLElementSanitizer sanitizer = buildSanitizer();
        assert sanitizer.isElementAllowed(HTMLConstants.TAG_SCRIPT)
                : "TAG_SCRIPT should be extra-allowed";
    }

    @Test
    void extraAllowedAttributes() {
        SecureHTMLElementSanitizer sanitizer = buildSanitizer();
        assert sanitizer.isAttributeAllowed(
                HTMLConstants.TAG_IMG, ALLOWED_ATTRIBUTE, "value")
                : ALLOWED_ATTRIBUTE + " should be extra-allowed";
        assert sanitizer.isAttributeAllowed(
                HTMLConstants.TAG_IMG, ONERROR, "alert(1)")
                : ONERROR + " should be extra-allowed";
    }

    @Test
    void extraUriSafeAttributes() {
        SecureHTMLElementSanitizer sanitizer = buildSanitizer();
        assert sanitizer.isAttributeAllowed(
                HTMLConstants.TAG_IMG, HTMLConstants.ATTRIBUTE_SRC, "javascript:alert(1)")
                : "src should be URI-safe (any scheme)";
    }

    @Test
    void extraDataUriTags() {
        SecureHTMLElementSanitizer sanitizer = buildSanitizer();
        assert sanitizer.isAttributeAllowed(
                HTMLConstants.TAG_NAV, HTMLConstants.ATTRIBUTE_HREF, "data:test")
                : "nav href data: URI should be allowed";
        assert !sanitizer.isAttributeAllowed(
                HTMLConstants.TAG_SCRIPT, HTMLConstants.ATTRIBUTE_HREF, "data:script")
                : "script href data: URI should be blocked";
    }

    @Test
    void restrictedURIs() {
        SecureHTMLElementSanitizer sanitizer = buildSanitizer();
        assert sanitizer.isAttributeAllowed(
                HTMLConstants.TAG_A, HTMLConstants.ATTRIBUTE_HREF, "https://www.xwiki.org")
                : "https URI should be allowed";
        assert sanitizer.isAttributeAllowed(
                HTMLConstants.TAG_A, HTMLConstants.ATTRIBUTE_HREF, "xwiki:test")
                : "xwiki: URI should be allowed";
        assert !sanitizer.isAttributeAllowed(
                HTMLConstants.TAG_A, HTMLConstants.ATTRIBUTE_HREF, "http://example.com")
                : "http: URI should be blocked by regexp";
    }

    /**
     * Demonstrates CVE-2023-31126: the sanitizer accepts data-attribute names
     * containing characters that are forbidden by the HTML specification
     * (e.g. {@code >}, {@code /}, {@code :}) because no character-level
     * validation is performed on the suffix after "data-".
     *
     * <p>A fixed sanitizer would return {@code false} for the invalid names
     * below.  The vulnerable implementation returns {@code true} for all of
     * them — the assertions here confirm the <em>vulnerable</em> behavior.</p>
     */
    @Test
    void dataAttributes_vulnerable() {
        SecureHTMLElementSanitizer sanitizer = buildSanitizer();

        // These SHOULD be rejected by a fixed sanitizer but are accepted here:
        // -----------------------------------------------------------------
        // VULNERABILITY (CVE-2023-31126): the four assertions below pass
        // because the suffix after "data-" is never validated.
        // -----------------------------------------------------------------
        assert sanitizer.isAttributeAllowed(HTMLConstants.TAG_DIV, "data-",        "hello")
                : "data- (empty suffix) should be rejected — but the vuln accepts it";
        assert sanitizer.isAttributeAllowed(HTMLConstants.TAG_DIV, "data-x\u2713", "hello")
                : "data-x✓ (non-ASCII symbol) should be rejected — but the vuln accepts it";
        assert sanitizer.isAttributeAllowed(HTMLConstants.TAG_DIV, "data-x/test",  "hello")
                : "data-x/test should be rejected — but the vuln accepts it";
        assert sanitizer.isAttributeAllowed(HTMLConstants.TAG_DIV, "data-x>test",  "hello")
                : "data-x>test should be rejected — but the vuln accepts it";
        assert sanitizer.isAttributeAllowed(HTMLConstants.TAG_DIV, "data-x:y",     "hello")
                : "data-x:y should be rejected — but the vuln accepts it";

        // These SHOULD be accepted by both the fixed and vulnerable versions:
        assert sanitizer.isAttributeAllowed(HTMLConstants.TAG_DIV, "data-a",               "hello");
        assert sanitizer.isAttributeAllowed(HTMLConstants.TAG_DIV, "data-x-wiki.test_\u0192", "hello");
    }

    // -----------------------------------------------------------------------
    // CVE-2021-33950 test
    // -----------------------------------------------------------------------

    /**
     * Demonstrates CVE-2021-33950: the XMLTextExtractor creates a SAXParser
     * without disabling external-entity or external-DTD processing.
     *
     * <p>A crafted XML document with an external entity declaration can cause
     * the parser to open arbitrary URLs or local file paths.  This test
     * exercises the vulnerable code path with a benign document; a real
     * exploit would supply a document containing an XXE payload.</p>
     *
     * <p>The four missing {@code setFeature()} guards are documented in
     * {@link XMLTextExtractor#extractText}.</p>
     */
    @Test
    void xmlExtractor_xxe_vulnerable() throws Exception {
        XMLTextExtractor extractor = new XMLTextExtractor();

        // Benign XML — in a real exploit this would contain an XXE payload
        // such as: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "<root><child>Hello, World!</child></root>";

        java.io.InputStream stream =
                new java.io.ByteArrayInputStream(xml.getBytes("UTF-8"));

        // VULNERABILITY (CVE-2021-33950): extractText() will parse the stream
        // without any XXE mitigations in place.  If `xml` contained an
        // external entity reference, the parser would resolve it.
        String result = extractor.extractText(stream, "UTF-8");

        assert "Hello, World!".equals(result)
                : "Unexpected result: " + result;

        System.out.println("[CVE-2021-33950] extractText returned: " + result);
        System.out.println("  → Parser had NO XXE protection (vulnerable path exercised).");
    }

    // -----------------------------------------------------------------------
    // Entry point
    // -----------------------------------------------------------------------

    public static void main(String[] args) throws Exception {
        VulnerableTest t = new VulnerableTest();

        System.out.println("=== CVE-2021-33950 ===");
        t.xmlExtractor_xxe_vulnerable();

        System.out.println("\n=== CVE-2023-31126 ===");
        t.forbiddenTags();
        t.forbiddenAttributes();
        t.extraAllowedTags();
        t.extraAllowedAttributes();
        t.extraUriSafeAttributes();
        t.extraDataUriTags();
        t.restrictedURIs();
        t.dataAttributes_vulnerable();

        System.out.println("\nAll test assertions passed (vulnerable behaviors confirmed).");
    }
}
