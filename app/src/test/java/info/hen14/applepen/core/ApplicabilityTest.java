package info.hen14.applepen.core;

import org.junit.Test;
import static org.junit.Assert.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

@SuppressWarnings("unchecked")
public class ApplicabilityTest {
    private static final String NGINX="cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*";
    private static final String SSH="cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*";
    private static final String OS="cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*";
    private final ProductFingerprint product=ProductFingerprint.detect("Server: nginx/1.24.0");
    private Map<String,Object> criterion(String cpe,boolean vulnerable,String... bounds) {
        Map<String,Object> rule=new LinkedHashMap<>(); rule.put("criteria",cpe);rule.put("vulnerable",vulnerable);rule.put("matchCriteriaId","00000000-0000-0000-0000-000000000001");
        for(int i=0;i<bounds.length;i+=2)rule.put(bounds[i],bounds[i+1]); return rule;
    }
    private Map<String,Object> node(String op,Map<String,Object>... rules) { return new LinkedHashMap<>(Map.of("operator",op,"negate",false,"cpeMatch",Arrays.asList(rules))); }
    private Map<String,Object> config(String op,Map<String,Object>... nodes) { return new LinkedHashMap<>(Map.of("operator",op,"nodes",Arrays.asList(nodes))); }
    private Map<String,Object> cve(Map<String,Object>... configs) { return new LinkedHashMap<>(Map.of("configurations",Arrays.asList(configs))); }
    private NvdApplicability.Result evaluate(Map<String,Object> rule) { return NvdApplicability.evaluate(cve(config("OR",node("OR",rule))),product); }
    private String json(Object value) {
        if(value instanceof Map) { StringJoiner j=new StringJoiner(",","{","}"); for(Map.Entry<?,?> e:((Map<?,?>)value).entrySet()) j.add(ReportExporter.quote((String)e.getKey())+":"+json(e.getValue()));return j.toString(); }
        if(value instanceof List) { StringJoiner j=new StringJoiner(",","[","]");for(Object v:(List<?>)value)j.add(json(v));return j.toString(); }
        return value instanceof String ? ReportExporter.quote((String)value) : String.valueOf(value);
    }
    private CveLookup.Result records(Map<String,Object>... cves) {
        List<Object> records=new ArrayList<>();for(Map<String,Object> c:cves)records.add(Map.of("cve",c));
        return NvdData.findings(json(Map.of("totalResults",cves.length,"vulnerabilities",records)),product,"cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*",8089,"Synthetic source timestamp");
    }
    private Map<String,Object> record(String id,Map<String,Object> body) {
        Map<String,Object> c=new LinkedHashMap<>(body);c.put("id",id);c.put("vulnStatus","Analyzed");c.put("metrics",Map.of("cvssMetricV31",List.of(Map.of("type","Primary","cvssData",Map.of("baseSeverity","HIGH","baseScore",8.1)))));return c;
    }
    @Test public void numericVersionOrderingHandlesMultiDigitSegmentsAndTrailingZeros() {
        assertTrue(VersionNumbers.compare("1.9.0","1.10.0")<0); assertEquals(Integer.valueOf(0),VersionNumbers.compare("1.24","1.24.0"));
        assertTrue(VersionNumbers.compare("9.6p2","9.6p10")<0); assertTrue(VersionNumbers.compare("9.5p1","9.6")<0);
        assertNull(VersionNumbers.compare("9.6p1","9.6")); assertNull(VersionNumbers.compare("1.24.0-rc1","1.24.0"));
        for(String v:new String[]{"1.2.0+vendor","01.24","1","1.2.3.4.5","1.9999999999","1.2p01","1.2.*"}) assertNull(VersionNumbers.parse(v));
    }
    @Test public void inclusiveAndExclusiveLowerBoundariesAreApplied() {
        assertEquals(NvdApplicability.Outcome.RULE_MATCHED,evaluate(criterion(NGINX,true,"versionStartIncluding","1.24.0")).outcome);
        assertEquals(NvdApplicability.Outcome.VERSION_EXCLUDED,evaluate(criterion(NGINX,true,"versionStartExcluding","1.24.0")).outcome);
        assertEquals(NvdApplicability.Outcome.VERSION_EXCLUDED,evaluate(criterion(NGINX,true,"versionStartIncluding","1.25.0")).outcome);
    }
    @Test public void inclusiveAndExclusiveUpperBoundariesAreApplied() {
        assertEquals(NvdApplicability.Outcome.RULE_MATCHED,evaluate(criterion(NGINX,true,"versionEndIncluding","1.24.0")).outcome);
        assertEquals(NvdApplicability.Outcome.VERSION_EXCLUDED,evaluate(criterion(NGINX,true,"versionEndExcluding","1.24.0")).outcome);
        assertEquals(NvdApplicability.Outcome.RULE_MATCHED,evaluate(criterion(NGINX,true,"versionStartIncluding","1.10.0","versionEndExcluding","1.25.0")).outcome);
    }
    @Test public void literalVersionsAreCheckedWithoutLoosePunctuationNormalization() {
        assertEquals(NvdApplicability.Outcome.RULE_MATCHED,evaluate(criterion(NGINX.replaceFirst(java.util.regex.Pattern.quote(":*:*:"),":1.24.0:*:"),true)).outcome);
        assertEquals(NvdApplicability.Outcome.VERSION_EXCLUDED,evaluate(criterion(NGINX.replaceFirst(java.util.regex.Pattern.quote(":*:*:"),":1.25.0:*:"),true)).outcome);
        assertEquals(NvdApplicability.Outcome.UNKNOWN,evaluate(criterion(NGINX.replaceFirst(java.util.regex.Pattern.quote(":*:*:"),":1.24.0-rc1:*:"),true)).outcome);
        assertFalse(product.matchesCpe("cpe:2.3:a:nginx:nginx:1-24.0:*:*:*:*:*:*:*"));
        assertNull(ProductFingerprint.detect("Server: nginx/1.24.0p1"));
    }
    @Test public void unsupportedAndContradictoryRangesRemainUnknown() {
        for(Map<String,Object> r:List.of(criterion(NGINX,true,"versionEndExcluding","1.24.0-rc1"),criterion(NGINX,true,"versionStartIncluding","2.0.0","versionEndIncluding","1.0.0"),criterion(NGINX,true,"versionStartIncluding","1.24.0","versionEndExcluding","1.24.0"),criterion(NGINX,true,"versionStartIncluding","1.0.0","versionStartExcluding","1.1.0"))) assertEquals(NvdApplicability.Outcome.UNKNOWN,evaluate(r).outcome);
        Map<String,Object> wrongType=criterion(NGINX,true);wrongType.put("versionEndIncluding",123);assertEquals(NvdApplicability.Outcome.UNKNOWN,evaluate(wrongType).outcome);
    }
    @Test public void opensshPortableUpdateMatchingAndAmbiguousBoundariesAreConservative() {
        ProductFingerprint p=ProductFingerprint.detect("SSH-2.0-OpenSSH_9.6p1");
        Map<String,Object> exact=criterion(SSH.replaceFirst(java.util.regex.Pattern.quote(":*:*:"),":9.6:p1:"),true);
        assertEquals(NvdApplicability.Outcome.RULE_MATCHED,NvdApplicability.evaluate(cve(config("OR",node("OR",exact))),p).outcome);
        assertEquals(NvdApplicability.Outcome.UNKNOWN,NvdApplicability.evaluate(cve(config("OR",node("OR",criterion(SSH,true,"versionEndIncluding","9.6")))),p).outcome);
        assertEquals(NvdApplicability.Outcome.VERSION_EXCLUDED,NvdApplicability.evaluate(cve(config("OR",node("OR",criterion(SSH,true,"versionEndExcluding","9.6p1")))),p).outcome);
        assertEquals(NvdApplicability.Outcome.RULE_MATCHED,NvdApplicability.evaluate(cve(config("OR",node("OR",criterion(SSH.replaceFirst(java.util.regex.Pattern.quote(":*:*:"),":9.6:*:"),true)))),p).outcome);
        assertEquals(NvdApplicability.Outcome.UNKNOWN,NvdApplicability.evaluate(cve(config("OR",node("OR",criterion(SSH.replaceFirst(java.util.regex.Pattern.quote(":*:*:"),":*:-:"),true)))),p).outcome);
    }
    @Test public void andPrerequisitesAreUnknownRatherThanAssumedPresentOrAbsent() {
        NvdApplicability.Result r=NvdApplicability.evaluate(cve(config("AND",node("OR",criterion(NGINX,true)),node("OR",criterion(OS,false)))),product);
        assertEquals(NvdApplicability.Outcome.PREREQUISITES_UNVERIFIED,r.outcome); assertTrue(r.rules.stream().anyMatch(x->x.contains("vulnerable=false")));
    }
    @Test public void sameProductAsEnvironmentPrerequisiteDoesNotEstablishVulnerability() {
        assertEquals(NvdApplicability.Outcome.UNKNOWN,evaluate(criterion(NGINX,false)).outcome);
        NvdApplicability.Result r=NvdApplicability.evaluate(cve(config("OR",node("OR",criterion(NGINX,false),criterion(SSH,true)))),product);
        assertEquals(NvdApplicability.Outcome.PRODUCT_EXCLUDED,r.outcome);
    }
    @Test public void orAlternativeWithOneMatchingProductRuleDoesNotRequireUnrelatedSoftware() {
        NvdApplicability.Result r=NvdApplicability.evaluate(cve(config("OR",node("OR",criterion(NGINX,true),criterion(SSH,true)))),product);
        assertEquals(NvdApplicability.Outcome.RULE_MATCHED,r.outcome);
    }
    @Test public void unknownAlternativePreventsExclusionEvenWhenKnownVersionIsOutsideRange() {
        NvdApplicability.Result r=NvdApplicability.evaluate(cve(config("OR",node("OR",criterion(NGINX,true,"versionEndExcluding","1.20.0"),criterion("cpe:2.3:a:*:nginx:*:*:*:*:*:*:*:*",true)))),product);
        assertEquals(NvdApplicability.Outcome.UNKNOWN,r.outcome);
    }
    @Test public void multipleConfigurationsCanProvideAnIndependentMatchingAlternative() {
        NvdApplicability.Result r=NvdApplicability.evaluate(cve(config("AND",node("OR",criterion(NGINX,true)),node("OR",criterion(OS,false))),config("OR",node("OR",criterion(NGINX,true)))),product);
        assertEquals(NvdApplicability.Outcome.RULE_MATCHED,r.outcome);
    }
    @Test public void conjunctionOfDistinctSameProductVersionsDoesNotInferHostInventoryAbsence() {
        NvdApplicability.Result r=NvdApplicability.evaluate(cve(config("AND",node("OR",criterion(NGINX.replaceFirst(java.util.regex.Pattern.quote(":*:*:"),":1.24.0:*:"),true)),node("OR",criterion(NGINX.replaceFirst(java.util.regex.Pattern.quote(":*:*:"),":1.25.0:*:"),true)))),product);
        assertEquals(NvdApplicability.Outcome.PREREQUISITES_UNVERIFIED,r.outcome);
    }
    @Test public void platformAndEditionConstraintsStayUnverified() {
        assertEquals(NvdApplicability.Outcome.PREREQUISITES_UNVERIFIED,evaluate(criterion("cpe:2.3:a:nginx:nginx:*:*:*:*:*:linux:*:*",true)).outcome);
        assertEquals(NvdApplicability.Outcome.UNKNOWN,evaluate(criterion("cpe:2.3:a:nginx:nginx:1.2.*:*:*:*:*:*:*:*",true)).outcome);
    }
    @Test public void negationIsRetainedForManualReviewInsteadOfProducingAnInvertedVulnerability() {
        Map<String,Object> n=node("OR",criterion(NGINX,true,"versionEndIncluding","1.0.0"));n.put("negate",true);
        assertEquals(NvdApplicability.Outcome.UNKNOWN,NvdApplicability.evaluate(cve(config("OR",n)),product).outcome);
        Map<String,Object> c=config("OR",node("OR",criterion(NGINX,true)));c.put("negate",true);
        assertEquals(NvdApplicability.Outcome.UNKNOWN,NvdApplicability.evaluate(cve(c),product).outcome);
    }
    @Test public void missingMalformedOrFutureConfigurationShapesNeverSuppressCandidates() {
        for(Map<String,Object> c:List.of(Map.<String,Object>of(),Map.<String,Object>of("configurations",List.of()),Map.<String,Object>of("configurations","bad"))) assertEquals(NvdApplicability.Outcome.UNKNOWN,NvdApplicability.evaluate(c,product).outcome);
        Map<String,Object> n=node("OR",criterion(NGINX,true,"versionEndIncluding","1.0.0"));n.put("children",List.of());assertEquals(NvdApplicability.Outcome.UNKNOWN,NvdApplicability.evaluate(cve(config("OR",n)),product).outcome);
        Map<String,Object> m=criterion(NGINX,true);m.put("futureCondition","unknown");assertEquals(NvdApplicability.Outcome.UNKNOWN,evaluate(m).outcome);
        m=criterion(NGINX,true);m.put("vulnerable","true");assertEquals(NvdApplicability.Outcome.UNKNOWN,evaluate(m).outcome);
    }
    @Test public void affectedSourceDataIsNotSilentlyOverriddenByCpeConfigurationResults() {
        Map<String,Object> c=cve(config("OR",node("OR",criterion(NGINX,true,"versionEndIncluding","1.0.0"))));c.put("affected",List.of(Map.of("source","vendor","affectedData",List.of())));
        assertEquals(NvdApplicability.Outcome.UNKNOWN,NvdApplicability.evaluate(c,product).outcome);
    }
    @Test public void singleNodeConfigurationNeedsNoInventedDefaultForMultipleNodes() {
        Map<String,Object> c=config("OR",node("OR",criterion(NGINX,true)));c.remove("operator");assertEquals(NvdApplicability.Outcome.RULE_MATCHED,NvdApplicability.evaluate(cve(c),product).outcome);
        c=config("OR",node("OR",criterion(NGINX,true)),node("OR",criterion(OS,false)));c.remove("operator");assertEquals(NvdApplicability.Outcome.UNKNOWN,NvdApplicability.evaluate(cve(c),product).outcome);
    }
    @Test public void boundedWorkAndEvidenceCannotTurnTruncatedInputIntoAnExclusion() {
        List<Map<String,Object>> terms=new ArrayList<>();for(int i=0;i<513;i++)terms.add(criterion(NGINX,true,"versionEndIncluding","1.0.0"));
        Map<String,Object> n=Map.of("operator","OR","cpeMatch",terms);
        NvdApplicability.Result r=NvdApplicability.evaluate(cve(config("OR",n)),product);assertEquals(NvdApplicability.Outcome.UNKNOWN,r.outcome);assertTrue(r.rules.size()<=12);
        List<Map<String,Object>> configs=new ArrayList<>();for(int i=0;i<33;i++)configs.add(config("OR",node("OR",criterion(NGINX,true))));
        assertEquals(NvdApplicability.Outcome.UNKNOWN,NvdApplicability.evaluate(Map.of("configurations",configs),product).outcome);
    }
    @Test public void matchingRuleEvidenceIsPreservedWhenManyUnmatchedRulesAreTruncated() {
        List<Map<String,Object>> terms=new ArrayList<>();for(int i=0;i<20;i++)terms.add(criterion(NGINX,true,"versionEndIncluding","1.0.0"));terms.add(criterion(NGINX,true,"versionStartIncluding","1.24.0"));
        NvdApplicability.Result r=NvdApplicability.evaluate(cve(config("OR",Map.of("operator","OR","cpeMatch",terms))),product);
        assertEquals(NvdApplicability.Outcome.RULE_MATCHED,r.outcome);assertTrue(r.rules.get(0).contains("banner result=YES"));assertTrue(r.rules.stream().anyMatch(x->x.contains("evidence omitted")));assertTrue(r.rules.size()<=12);
    }
    @Test public void formattedCpeReaderHandlesEscapedColonsWithoutShiftingFields() {
        CpeName c=CpeName.parse("cpe:2.3:a:nginx:nginx:1.24.0:*:edition\\:name:*:*:*:*:*");assertNotNull(c);assertEquals("edition\\:name",c.field(7));assertEquals("*",c.field(8));
        for(String s:new String[]{"cpe:/a:nginx:nginx:1.24.0","cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:",NGINX+"\\",NGINX+":extra"})assertNull(CpeName.parse(s));
    }
    @Test public void dictionarySelectionPrefersGenericNamesAndRequiresExplicitNonDeprecation() {
        String generic=NGINX.replaceFirst(java.util.regex.Pattern.quote(":*:*:"),":1.24.0:*:"), specific="cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:linux:*:*";
        String response=json(Map.of("totalResults",2,"products",List.of(Map.of("cpe",Map.of("deprecated",false,"cpeName",specific)),Map.of("cpe",Map.of("deprecated",false,"cpeName",generic)))));
        assertEquals(generic,NvdData.selectCpe(response,product));
        assertEquals("",NvdData.selectCpe(json(Map.of("totalResults",1,"products",List.of(Map.of("cpe",Map.of("cpeName",generic))))),product));
    }
    @Test public void dictionaryPageCapAndResultCountsAreValidated() {
        List<Object> names=new ArrayList<>();for(int i=0;i<20;i++)names.add(Map.of("cpe",Map.of("deprecated",false,"cpeName",NGINX.replaceFirst(java.util.regex.Pattern.quote(":*:*:"),":1.25.0:*:"))));
        names.add(Map.of("cpe",Map.of("deprecated",false,"cpeName",NGINX.replaceFirst(java.util.regex.Pattern.quote(":*:*:"),":1.24.0:*:"))));assertEquals("",NvdData.selectCpe(json(Map.of("totalResults",21,"products",names)),product));
        for(String count:List.of("-1","1.5","2147483648"))assertThrows(IllegalArgumentException.class,()->NvdData.selectCpe("{\"totalResults\":"+count+",\"products\":[]}",product));
    }
    @Test public void excludedRecordsAreAuditedAndRetainedRecordsRemainLowConfidencePotentialCves() {
        CveLookup.Result r=records(record("CVE-2099-90000001",cve(config("OR",node("OR",criterion(NGINX,true,"versionEndExcluding","1.24.0"))))),record("CVE-2099-90000002",cve(config("OR",node("OR",criterion(NGINX,true))))),record("CVE-2099-90000003",Map.of()));
        assertEquals(2,r.findings.size());for(ScanReport.Finding f:r.findings){assertEquals("Potential CVE",f.status);assertEquals("Low",f.confidence);assertEquals("High",f.severity);assertNotNull(f.cve);}
        assertTrue(r.coverage.stream().anyMatch(x->x.startsWith("CVE-2099-90000001 excluded")));assertTrue(r.coverage.stream().anyMatch(x->x.contains("1 matched; 0 with unverified prerequisites; 1 unknown; 1 excluded")));
    }
    @Test public void applicabilityMetadataSurvivesSerializationAndEscapedExports() throws Exception {
        ScanReport r=new ScanReport(new ScanConfig("127.0.0.1","","Custom","8089",300,1));r.findings.addAll(records(record("CVE-2099-90000002",cve(config("AND",node("OR",criterion(NGINX,true)),node("OR",criterion(OS,false)))))).findings);
        ByteArrayOutputStream b=new ByteArrayOutputStream();try(ObjectOutputStream out=new ObjectOutputStream(b)){out.writeObject(r);}try(ObjectInputStream in=new ObjectInputStream(new ByteArrayInputStream(b.toByteArray()))){r=(ScanReport)in.readObject();}
        Map<String,Object> export=JsonReader.object(JsonReader.parse(ReportExporter.json(r)));assertEquals(4,JsonReader.integer(export.get("schemaVersion")));Map<String,Object> assessment=JsonReader.object(JsonReader.object(JsonReader.array(export.get("findings")).get(0)).get("cveAssessment"));
        assertEquals("Configuration prerequisites unverified",assessment.get("applicability"));assertTrue(ReportExporter.html(r).contains("Environment prerequisite"));assertTrue(String.join("\n",ReportExporter.text(r)).contains("CVE applicability"));
    }
    @Test public void duplicatedAndRejectedRecordsDoNotInflateCandidateCounts() {
        Map<String,Object> c=record("CVE-2099-90000002",Map.of()),rejected=record("CVE-2099-90000003",Map.of());rejected.put("vulnStatus","Rejected");
        assertEquals(1,records(c,c,rejected).findings.size());
    }
    @Test public void reportComparisonRecognizesChangesInApplicabilityClassification() {
        ScanConfig c=new ScanConfig("127.0.0.1","","Custom","8089",300,1);ScanReport before=new ScanReport(c),after=new ScanReport(c);before.status=after.status="Completed";
        before.findings.add(records(record("CVE-2099-90000002",Map.of())).findings.get(0));after.findings.add(records(record("CVE-2099-90000002",cve(config("OR",node("OR",criterion(NGINX,true)))))).findings.get(0));
        assertEquals(1,ReportDiff.compare(before,after).changedFindings);
    }
    @Test public void v030CveReportsKeepTheirVersionAndHaveNoInventedApplicability() throws Exception {
        try(ObjectInputStream in=new ObjectInputStream(getClass().getResourceAsStream("/legacy-v030.report"))) {
            ScanReport legacy=(ScanReport)in.readObject();assertEquals("0.3.0",legacy.version());assertTrue(legacy.config.protocolChecks);assertTrue(legacy.config.enumerateTls);assertTrue(legacy.config.lookupCves);assertNull(legacy.findings.get(0).cve);
            assertTrue(ReportExporter.json(legacy).contains("\"cveAssessment\":null"));assertTrue(ReportExporter.html(legacy).contains("Synthetic legacy evidence"));
        }
    }
    @Test public void enginePreservesApplicabilityWhenOneProductAppearsOnMultiplePorts() throws Exception {
        try(ServerSocket one=new ServerSocket(0);ServerSocket two=new ServerSocket(0)) {
            List<Thread> threads=new ArrayList<>();for(ServerSocket server:List.of(one,two)){server.setSoTimeout(3000);Thread t=new Thread(()->{for(int i=0;i<2;i++)try(Socket s=server.accept()){s.setSoTimeout(1000);BufferedReader reader=new BufferedReader(new InputStreamReader(s.getInputStream(),StandardCharsets.US_ASCII));if(reader.readLine()==null)continue;String line;while((line=reader.readLine())!=null&&!line.isEmpty()){}s.getOutputStream().write("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));}catch(Exception ignored){} });t.start();threads.add(t);}
            AtomicInteger calls=new AtomicInteger();CveLookup lookup=new CveLookup(){public Result lookup(ProductFingerprint p,int port){calls.incrementAndGet();return records(record("CVE-2099-90000002",cve(config("OR",node("OR",criterion(NGINX,true))))));}public void cancel(){}};
            String ports=one.getLocalPort()+","+two.getLocalPort();ScanReport r=new ScanEngine(lookup).run(new ScanConfig("127.0.0.1","","Custom",ports,500,2,ports,"",true),"fixture",(d,t,m)->{});
            for(Thread t:threads)t.join(4000);assertEquals(1,calls.get());List<ScanReport.Finding> candidates=new ArrayList<>();for(ScanReport.Finding f:r.findings)if(f.cve!=null)candidates.add(f);assertEquals(2,candidates.size());assertNotEquals(candidates.get(0).port,candidates.get(1).port);assertEquals("Product/version rule matched",candidates.get(1).cve.applicability);
        }
    }
}
