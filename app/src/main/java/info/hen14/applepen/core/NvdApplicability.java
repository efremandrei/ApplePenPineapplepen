package info.hen14.applepen.core;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Conservative product-instance checks of NVD 2.0's configurations/nodes/cpeMatch shape.
 * Other software and environment facts are unknown, not absent. This is not full CPE conformance.
 */
public final class NvdApplicability {
    public enum Outcome { RULE_MATCHED, PREREQUISITES_UNVERIFIED, UNKNOWN, VERSION_EXCLUDED, PRODUCT_EXCLUDED }
    private enum Truth { YES, NO, UNKNOWN }
    public static final class Result {
        public final Outcome outcome;
        public final String reason;
        public final ArrayList<String> rules;
        Result(Outcome outcome,String reason,List<String> rules) { this.outcome=outcome; this.reason=reason; this.rules=new ArrayList<>(rules); }
        public boolean retained() { return outcome!=Outcome.VERSION_EXCLUDED && outcome!=Outcome.PRODUCT_EXCLUDED; }
        public CveAssessment assessment(ProductFingerprint product,String cpe) {
            String label=switch(outcome) { case RULE_MATCHED -> "Product/version rule matched"; case PREREQUISITES_UNVERIFIED -> "Configuration prerequisites unverified"; default -> "Applicability unknown"; };
            return new CveAssessment(product,cpe,label,reason,rules);
        }
    }
    private final ProductFingerprint product;
    private final ArrayList<String> evidence=new ArrayList<>(), environmentEvidence=new ArrayList<>();
    private int evidenceCount;
    private int nodes, terms, positiveKnown, positiveExcluded, positiveMatched, positiveUnknown;
    private boolean unsupported;
    private NvdApplicability(ProductFingerprint product) { this.product=product; }
    public static Result evaluate(Map<String,Object> cve,ProductFingerprint product) {
        NvdApplicability e=new NvdApplicability(product);
        Object configs=cve.get("configurations");
        if(!(configs instanceof List) || ((List<?>)configs).isEmpty()) return e.result(Outcome.UNKNOWN,"No usable NVD CPE configuration statements were supplied.");
        List<?> values=(List<?>)configs;
        if(values.size()>32) return e.result(Outcome.UNKNOWN,"Configuration check capped at 32 configurations per CVE; applicability remains unknown.");
        ArrayList<Truth> results=new ArrayList<>();
        for(Object config:values) results.add(e.config(config));
        if(e.unsupported) return e.result(Outcome.UNKNOWN,"Unsupported, malformed, negated, or capped CPE configuration data requires manual review. No exclusion was inferred.");
        if(cve.containsKey("affected") && (!(cve.get("affected") instanceof List) || !((List<?>)cve.get("affected")).isEmpty())) return e.result(Outcome.UNKNOWN,"Additional affected-source data is present and was not evaluated; review the source record and vendor advisory.");
        if(e.positiveUnknown>0 && e.positiveMatched==0) return e.result(Outcome.UNKNOWN,"A potentially relevant vulnerable-product rule could not be resolved from this banner/version.");
        if(e.positiveMatched>0) {
            if(results.contains(Truth.YES)) return e.result(Outcome.RULE_MATCHED,"The banner satisfies a vulnerable product/version rule in a supported configuration. Banner identity, actual installation, vendor backports, and exploitability remain unverified.");
            return e.result(Outcome.PREREQUISITES_UNVERIFIED,"A vulnerable product/version rule matches, but additional configuration or environment conditions cannot be established from this service banner.");
        }
        if(e.positiveExcluded>0 && e.positiveUnknown==0) return e.result(Outcome.VERSION_EXCLUDED,"Every recognized vulnerable rule for this product excludes the observed banner version. This only excludes this candidate for the observed product instance; other installed software and patch status were not assessed.");
        if(e.positiveKnown>0 && e.positiveUnknown==0) return e.result(Outcome.PRODUCT_EXCLUDED,"The supported statements name different vulnerable products; the observed product is not named as vulnerable. Other software on this host was not assessed.");
        return e.result(Outcome.UNKNOWN,"No resolved vulnerable-product rule was available; environment prerequisites alone do not establish applicability.");
    }
    private Result result(Outcome o,String reason) {
        ArrayList<String> saved=new ArrayList<>(evidence);
        for(String line:environmentEvidence) if(saved.size()<12) saved.add(line);
        if(evidenceCount>saved.size()) { if(saved.size()==12) saved.remove(11); saved.add("Additional rule evidence omitted; review the full NVD configuration statements."); }
        return new Result(o,reason,saved);
    }
    private Truth bad() { unsupported=true; return Truth.UNKNOWN; }
    private boolean negatedOrInvalid(Map<String,Object> value) { return value.containsKey("negate") && !Boolean.FALSE.equals(value.get("negate")); }
    private Truth config(Object value) {
        if(!(value instanceof Map)) return bad(); Map<String,Object> c=JsonReader.object(value);
        if(!java.util.Set.of("operator","negate","nodes").containsAll(c.keySet())) return bad();
        if(negatedOrInvalid(c) || c.containsKey("children") || c.containsKey("cpeMatch")) return bad();
        if(!(c.get("nodes") instanceof List) || ((List<?>)c.get("nodes")).isEmpty()) return bad();
        List<?> children=(List<?>)c.get("nodes");
        if(children.size()>128) return bad();
        String op=c.containsKey("operator") ? JsonReader.string(c.get("operator")) : children.size()==1 ? "OR" : "";
        if(!op.equals("OR") && !op.equals("AND")) return bad();
        ArrayList<Truth> values=new ArrayList<>(); for(Object n:children) values.add(node(n)); return combine(values,op);
    }
    private Truth node(Object value) {
        if(++nodes>128 || !(value instanceof Map)) return bad(); Map<String,Object> n=JsonReader.object(value);
        if(!java.util.Set.of("operator","negate","cpeMatch").containsAll(n.keySet())) return bad();
        if(negatedOrInvalid(n) || n.containsKey("children") || n.containsKey("nodes")) return bad();
        String op=JsonReader.string(n.get("operator")); if(!op.equals("OR") && !op.equals("AND")) return bad();
        if(!(n.get("cpeMatch") instanceof List) || ((List<?>)n.get("cpeMatch")).isEmpty()) return bad();
        List<?> matches=(List<?>)n.get("cpeMatch"); if(matches.size()>512) return bad();
        ArrayList<Truth> values=new ArrayList<>(); for(Object m:matches) values.add(match(m)); return combine(values,op);
    }
    private Truth match(Object value) {
        if(++terms>512 || !(value instanceof Map)) return bad(); Map<String,Object> m=JsonReader.object(value);
        if(!java.util.Set.of("vulnerable","criteria","matchCriteriaId","versionStartIncluding","versionStartExcluding","versionEndIncluding","versionEndExcluding").containsAll(m.keySet())) return bad();
        if(!(m.get("vulnerable") instanceof Boolean)) return bad();
        CpeName cpe=CpeName.parse(JsonReader.string(m.get("criteria"))); if(cpe==null) return bad();
        boolean vulnerable=Boolean.TRUE.equals(m.get("vulnerable")); int family=product.family(cpe);
        if(!vulnerable) { note("Environment prerequisite (vulnerable=false): " + JsonReader.string(m.get("criteria"))); return Truth.UNKNOWN; }
        if(family==0) { positiveKnown++; return Truth.UNKNOWN; }
        if(family<0) { positiveUnknown++; note("Wildcard/unsupported product rule: " + JsonReader.string(m.get("criteria"))); return Truth.UNKNOWN; }
        Truth version=version(cpe,m);
        String bounds=""; for(String key:new String[]{"versionStartIncluding","versionStartExcluding","versionEndIncluding","versionEndExcluding"}) if(m.containsKey(key)) bounds+="; " + key + "=" + JsonReader.string(m.get(key));
        noteRule("Vulnerable-product rule: " + JsonReader.string(m.get("criteria")) + bounds + "; banner result=" + version,version==Truth.YES);
        if(version==Truth.NO) { positiveExcluded++; return Truth.NO; }
        if(version==Truth.UNKNOWN) { positiveUnknown++; return Truth.UNKNOWN; }
        positiveMatched++;
        if(cpe.restrictions()>0) { note("Edition/language/platform constraints in this rule were not established from the banner."); return Truth.UNKNOWN; }
        return Truth.YES;
    }
    private void note(String text) { evidenceCount++; if(environmentEvidence.size()<12) environmentEvidence.add(HttpRules.clean(text)); }
    private void noteRule(String text,boolean matched) {
        evidenceCount++; String clean=HttpRules.clean(text);
        if(matched) { evidence.add(0,clean); if(evidence.size()>12) evidence.remove(12); }
        else if(evidence.size()<12) evidence.add(clean);
    }
    private Truth version(CpeName cpe,Map<String,Object> match) {
        Truth exact=exactVersion(cpe);
        String start=null,end=null; boolean startInclusive=false,endInclusive=false;
        for(String key:new String[]{"versionStartIncluding","versionStartExcluding","versionEndIncluding","versionEndExcluding"}) {
            if(!match.containsKey(key)) continue;
            String v=JsonReader.string(match.get(key)); if(VersionNumbers.parse(v)==null) return Truth.UNKNOWN;
            if(key.startsWith("versionStart")) { if(start!=null)return Truth.UNKNOWN; start=v; startInclusive=key.endsWith("Including"); }
            else { if(end!=null)return Truth.UNKNOWN; end=v; endInclusive=key.endsWith("Including"); }
        }
        if(start!=null && end!=null) { Integer order=VersionNumbers.compare(start,end); if(order==null || order>0 || order==0 && (!startInclusive || !endInclusive)) return Truth.UNKNOWN; }
        boolean unknown=exact==Truth.UNKNOWN;
        if(start!=null) { Integer c=VersionNumbers.compare(product.version,start); if(c==null)unknown=true; else if(c<0 || c==0 && !startInclusive)return Truth.NO; }
        if(end!=null) { Integer c=VersionNumbers.compare(product.version,end); if(c==null)unknown=true; else if(c>0 || c==0 && !endInclusive)return Truth.NO; }
        return exact==Truth.NO ? Truth.NO : unknown ? Truth.UNKNOWN : Truth.YES;
    }
    private Truth exactVersion(CpeName cpe) {
        String version=cpe.field(5),update=cpe.field(6); VersionNumbers observed=VersionNumbers.parse(product.version);
        if(observed==null || version.equals("-")) return Truth.UNKNOWN;
        if(!update.equals("*") && !update.equals("-") && (!product.product.equals("openssh") || !update.matches("p[0-9]{1,9}"))) return Truth.UNKNOWN;
        if(version.equals("*")) {
            if(update.equals("*")) return Truth.YES;
            if(update.equals("-")) return observed.hasPortable() ? Truth.UNKNOWN : Truth.YES;
            return product.version.equals(observed.base()+update) ? Truth.YES : Truth.NO;
        }
        VersionNumbers rule=VersionNumbers.parse(version); if(rule==null) return Truth.UNKNOWN;
        if(!update.equals("*") && !update.equals("-")) {
            if(rule.hasPortable()) return Truth.UNKNOWN;
            return product.version.equals(version+update) ? Truth.YES : Truth.NO;
        }
        if(update.equals("*") && !rule.hasPortable() && observed.hasPortable()) return observed.base().equals(version) ? Truth.YES : Truth.NO;
        return product.version.equals(version) ? Truth.YES : Truth.NO;
    }
    private static Truth combine(List<Truth> values,String op) {
        if(op.equals("OR")) return values.contains(Truth.YES) ? Truth.YES : values.contains(Truth.UNKNOWN) ? Truth.UNKNOWN : Truth.NO;
        return values.contains(Truth.NO) ? Truth.NO : values.contains(Truth.UNKNOWN) ? Truth.UNKNOWN : Truth.YES;
    }
}
