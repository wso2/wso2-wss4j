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

package org.apache.ws.security.saml;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.keyvalues.DSAKeyValue;
import org.apache.xml.security.keys.content.keyvalues.RSAKeyValue;
import org.apache.xml.security.signature.XMLSignature;

import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.common.AbstractSAMLObject;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.saml.saml1.core.*;

import org.opensaml.saml.saml1.core.impl.SubjectImpl;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Properties;

/**
 * Builds a WS SAML Assertion and inserts it into the SOAP Envelope. Refer to
 * the WS specification, SAML Token profile
 *
 * @author Davanum Srinivas (dims@yahoo.com).
 */
public class SAMLIssuerImpl implements SAMLIssuer {

    private static final Log log = LogFactory.getLog(SAMLIssuerImpl.class.getName());
//    public static final String CONF_SENDER_VOUCHES = "urn:oasis:names:tc:SAML:1.0:cm:sender-vouches";
//    public static final String CONF_HOLDER_KEY = "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key";

    private Assertion sa = null;

    private Document instanceDoc = null;

    private Properties properties = null;

    private Crypto issuerCrypto = null;
    private String issuerKeyPassword = null;
    private String issuerKeyName = null;

    private boolean senderVouches = true;

    private String[] confirmationMethods = new String[1];
    private Crypto userCrypto = null;
    private String username = null;
    
    /**
    * Flag indicating what format to put the subject's key material in when
    * NOT using Sender Vouches as the confirmation method.  The default is
    * to use ds:X509Data and include the entire certificate.  If this flag
    * is set to true, a ds:KeyValue is used instead with just the key material.
    */
    private boolean sendKeyValue = false;

    /**
     * Constructor.
     */
    public SAMLIssuerImpl() {
    }

    public SAMLIssuerImpl(Properties prop) {
        /*
         * if no properties .. just return an instance, the rest will be done
         * later or this instance is just used to handle certificate
         * conversions in this implementation
         */
        if (prop == null) {
            return;
        }
        properties = prop;

        String cryptoProp =
                properties.getProperty("org.apache.ws.security.saml.issuer.cryptoProp.file");
        if (cryptoProp != null) {
            issuerCrypto = CryptoFactory.getInstance(cryptoProp);
            issuerKeyName =
                    properties.getProperty("org.apache.ws.security.saml.issuer.key.name");
            issuerKeyPassword =
                    properties.getProperty("org.apache.ws.security.saml.issuer.key.password");
        }
        
        String sendKeyValueProp =
            properties.getProperty("org.apache.ws.security.saml.issuer.sendKeyValue");
        if (sendKeyValueProp != null) {
            sendKeyValue = Boolean.valueOf(sendKeyValueProp).booleanValue();
        }

        if ("senderVouches"
                .equals(properties.getProperty("org.apache.ws.security.saml.confirmationMethod"))) {
            confirmationMethods[0] = "urn:oasis:names:tc:SAML:1.0:cm:sender-vouches";
        } else if (
                "keyHolder".equals(properties.getProperty("org.apache.ws.security.saml.confirmationMethod"))) {
            confirmationMethods[0] = "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key";
            senderVouches = false;
        } else {
            // throw something here - this is a mandatory property
        }
    }

    /**
     * Creates a new <code>Assertion</code>.
     * <p/>
     * <p/>
     * A complete <code>Assertion</code> is constructed.
     *
     * @return Assertion
     */
    public Assertion newAssertion() { // throws Exception {
        log.debug("Begin add Assertion token...");

        /*
         * if (senderVouches == false && userCrypto == null) { throw
         * exception("need user crypto data to insert key") }
         */
        // Issuer must enable crypto functions to get the issuer's certificate
        String issuer =
                properties.getProperty("org.apache.ws.security.saml.issuer");
        String name =
                properties.getProperty("org.apache.ws.security.saml.subjectNameId.name");
        String qualifier =
                properties.getProperty("org.apache.ws.security.saml.subjectNameId.qualifier");
        NameIdentifier nameId = SAMLUtil.newSamlObject(NameIdentifier.class);
        nameId.setValue(name);
        nameId.setNameQualifier(qualifier);
//                    new AbstractSAMLObject(name, qualifier, "");
        String subjectIP = null;
        String authMethod = null;
        if ("password"
                .equals(properties.getProperty("org.apache.ws.security.saml.authenticationMethod"))) {
            authMethod =
                    AuthenticationStatement.PASSWORD_AUTHN_METHOD;
        }
        DateTime authInstant = new DateTime();
        Collection bindings = null;

        Subject subject = SAMLUtil.newSamlObject(Subject.class);
        subject.setNameIdentifier(nameId);
//                    new Subject(nameId,
//                            Arrays.asList(confirmationMethods),
//                            null,
//                            null);

//            new AuthenticationStatement(subject,
//                    authMethod,
//                    authInstant,
//                    subjectIP,
//                    null,
//                    bindings)}

        AuthenticationStatement authenticationStatement = SAMLUtil.newSamlObject(AuthenticationStatement.class);
        authenticationStatement.setAuthenticationMethod(authMethod);
        authenticationStatement.setAuthenticationInstant(authInstant);


        sa = SAMLUtil.newSamlObject(Assertion.class);
        sa.setIssuer(issuer);

//            Statement[] statements =
//                    {
//                        ;
//            sa =
//                    new Assertion(issuer,
//                            null,
//                            null,
//                            null,
//                            null,
//                            Arrays.asList(statements));

        if (!senderVouches) {
            KeyInfo ki = new KeyInfo(instanceDoc);
            try {
                X509Certificate[] certs =
                        userCrypto.getCertificates(username);
                if (sendKeyValue) {
                    PublicKey key = certs[0].getPublicKey();
                    String pubKeyAlgo = key.getAlgorithm();

                    if ("DSA".equalsIgnoreCase(pubKeyAlgo)) {
                        DSAKeyValue dsaKeyValue = new DSAKeyValue(instanceDoc, key);
                        ki.add(dsaKeyValue);
                    } else if ("RSA".equalsIgnoreCase(pubKeyAlgo)) {
                        RSAKeyValue rsaKeyValue = new RSAKeyValue(instanceDoc, key);
                        ki.add(rsaKeyValue);
                    }
                } else {
                    X509Data certElem = new X509Data(instanceDoc);
                    certElem.addCertificate(certs[0]);
                    ki.add(certElem);
                }
            } catch (WSSecurityException ex) {
                if (log.isDebugEnabled()) {
                    log.debug(ex.getMessage(), ex);
                }
                return null;
            } catch (XMLSecurityException ex) {
                if (log.isDebugEnabled()) {
                    log.debug(ex.getMessage(), ex);
                }
                return null;
            }
            Element keyInfoElement = ki.getElement();
            keyInfoElement.setAttributeNS(WSConstants.XMLNS_NS, "xmlns:"
                    + WSConstants.SIG_PREFIX, WSConstants.SIG_NS);

//                subject.setKeyInfo(ki);
            // prepare to sign the SAML token
            try {
                X509Certificate[] issuerCerts =
                        issuerCrypto.getCertificates(issuerKeyName);

                String sigAlgo = XMLSignature.ALGO_ID_SIGNATURE_RSA;
                String pubKeyAlgo =
                        issuerCerts[0].getPublicKey().getAlgorithm();
                log.debug("automatic sig algo detection: " + pubKeyAlgo);
                if (pubKeyAlgo.equalsIgnoreCase("DSA")) {
                    sigAlgo = XMLSignature.ALGO_ID_SIGNATURE_DSA;
                }
                java.security.Key issuerPK =
                        issuerCrypto.getPrivateKey(issuerKeyName,
                                issuerKeyPassword);
//                    sa.sign(sigAlgo, issuerPK, Arrays.asList(issuerCerts));
            } catch (WSSecurityException ex) {
                if (log.isDebugEnabled()) {
                    log.debug(ex.getMessage(), ex);
                }
                return null;
            } catch (Exception ex) {
                if (log.isDebugEnabled()) {
                    log.debug(ex.getMessage(), ex);
                }
                return null;
            }
        }
        return sa;
    }

    /**
     * @param userCrypto The userCrypto to set.
     */
    public void setUserCrypto(Crypto userCrypto) {
        this.userCrypto = userCrypto;
    }

    /**
     * @param username The username to set.
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * @return Returns the issuerCrypto.
     */
    public Crypto getIssuerCrypto() {
        return issuerCrypto;
    }

    /**
     * @return Returns the issuerKeyName.
     */
    public String getIssuerKeyName() {
        return issuerKeyName;
    }

    /**
     * @return Returns the issuerKeyPassword.
     */
    public String getIssuerKeyPassword() {
        return issuerKeyPassword;
    }

    /**
     * @return Returns the senderVouches.
     */
    public boolean isSenderVouches() {
        return senderVouches;
    }

    /**
     * @param instanceDoc The instanceDoc to set.
     */
    public void setInstanceDoc(Document instanceDoc) {
        this.instanceDoc = instanceDoc;
    }
}
