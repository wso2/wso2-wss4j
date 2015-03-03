/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package wssec;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSSecEncryptedKey;
import org.apache.ws.security.processor.EncryptedKeyProcessor;
import org.apache.xml.security.utils.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;


public class TestEncryptedKeyProcessor extends TestCase implements CallbackHandler {

    private static final Log LOG = LogFactory.getLog(TestEncryptedKeyProcessor.class);
    private Map<String, String> users = new HashMap<String, String>();
    private Crypto crypto = CryptoFactory.getInstance();
    public static final String SAMPLE_SOAP_MSG =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                    + "<SOAP-ENV:Envelope "
                    +   "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" "
                    +   "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
                    +   "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
                    +   "<SOAP-ENV:Body>"
                    +       "<add xmlns=\"http://ws.apache.org/counter/counter_port_type\">"
                    +           "<value xmlns=\"\">15</value>"
                    +       "</add>"
                    +   "</SOAP-ENV:Body>"
                    + "</SOAP-ENV:Envelope>";

    /**
     * TestWSSecurity constructor
     * <p/>
     *
     * @param name name of the test
     */
    public TestEncryptedKeyProcessor(String name) {
        super(name);
    }

    /**
     * JUnit suite
     * <p/>
     *
     * @return a junit test suite
     */
    public static Test suite() {
        return new TestSuite(TestEncryptedKeyProcessor.class);
    }

    /**
     * Setup method
     * <p/>
     *
     * @throws Exception Thrown when there is a problem in setup
     */
    protected void setUp() throws Exception {

        users.put("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
    }

    public void testKey() throws Exception {

        Document doc = SOAPUtil.toSOAPPart(SAMPLE_SOAP_MSG);

        WSSecEncryptedKey encrKey = new WSSecEncryptedKey();
        encrKey.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        encrKey.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        encrKey.setKeySize(128);
        encrKey.prepare(doc, crypto);

        verify(encrKey.getEncryptedKeyElement());

    }

    private void verify(Element enc)  {
        // Change the CipherValue of the key
        String str = enc.getLastChild().getFirstChild().getTextContent();
        enc.getLastChild().getFirstChild().setTextContent(Base64.encode(str.getBytes()));
        EncryptedKeyProcessor encryptedKeyProcessor = new EncryptedKeyProcessor();
        try {
            encryptedKeyProcessor.handleEncryptedKey(enc, this, crypto, null);

        } catch (Exception e) {
        LOG.error("Key validation error, Should create a new random key if key decrypting fails ");
        }


    }

    public void handle(Callback[] callbacks)
            throws IOException, UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof WSPasswordCallback) {
                WSPasswordCallback pc = (WSPasswordCallback) callbacks[i];
                pc.setPassword(users.get(pc.getIdentifier()));
            } else {
                throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
            }
        }
    }
}
