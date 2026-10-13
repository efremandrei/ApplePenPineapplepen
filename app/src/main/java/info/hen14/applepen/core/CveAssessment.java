package info.hen14.applepen.core;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/** Source-derived product-rule assessment. It never establishes exploitability or installed patch status. */
public final class CveAssessment implements Serializable {
    private static final long serialVersionUID = 1L;
    public final String product, version, dictionaryCpe, applicability, reason;
    public final ArrayList<String> rules;
    public CveAssessment(ProductFingerprint product,String cpe,String applicability,String reason,List<String> rules) {
        this.product=product.name; this.version=product.version; this.dictionaryCpe=cpe;
        this.applicability=applicability; this.reason=reason; this.rules=new ArrayList<>(rules);
    }
    public String evidence() { return "Applicability: " + applicability + "\n" + reason + (rules.isEmpty() ? "" : "\n" + String.join("\n",rules)); }
}
