package com.dpi.engine;

import com.dpi.inspect.HttpHostExtractor;
import com.dpi.inspect.SniExtractor;
import com.dpi.model.AppType;
import com.dpi.model.FiveTuple;
import com.dpi.model.Flow;

import java.util.Optional;

/** Decides what application a flow belongs to (SNI, then HTTP Host, then DNS, then port fallback). */
final class FlowClassifier {
    private FlowClassifier() {}

    static void classify(FiveTuple t, byte[] data, int payloadOffset, int payloadLength, Flow flow) {
        if (t.dstPort() == 443 && payloadLength > 5) {
            Optional<String> sni = SniExtractor.extract(data, payloadOffset, payloadLength);
            if (sni.isPresent()) {
                flow.sni = sni.get();
                flow.appType = AppType.fromSni(flow.sni);
                flow.classified = true;
                return;
            }
        }

        if (t.dstPort() == 80 && payloadLength > 10) {
            Optional<String> host = HttpHostExtractor.extract(data, payloadOffset, payloadLength);
            if (host.isPresent()) {
                flow.sni = host.get();
                flow.appType = AppType.fromSni(flow.sni);
                flow.classified = true;
                return;
            }
        }

        if (t.dstPort() == 53 || t.srcPort() == 53) {
            flow.appType = AppType.DNS;
            flow.classified = true;
            return;
        }

        // Port-based fallback. Not marked "classified": a later packet (Client Hello) may still reveal the SNI.
        if (t.dstPort() == 443) flow.appType = AppType.HTTPS;
        else if (t.dstPort() == 80) flow.appType = AppType.HTTP;
    }
}
