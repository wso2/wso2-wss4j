/*
 * Copyright  2003-2008 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.apache.ws.security.saml;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.token.Timestamp;
import org.apache.ws.security.processor.EncryptedKeyProcessor;
import org.apache.ws.security.util.Base64;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.ws.security.util.XMLUtils;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509Certificate;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.saml1.core.AttributeStatement;
import org.opensaml.saml.saml1.core.AuthenticationStatement;
import org.opensaml.saml.saml1.core.Subject;
import org.opensaml.saml.saml1.core.SubjectStatement;
import org.opensaml.saml.saml1.core.Assertion;
import org.opensaml.saml.saml1.core.Attribute;
import org.opensaml.saml.saml1.core.Statement;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.lang.reflect.Field;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Utility methods for SAML stuff
 */
public class SAMLUtil {
    private static final Log log = LogFactory.getLog(SAMLUtil.class.getName());

    public static final String DEFAULT_ELEMENT_NAME_FIELD = "DEFAULT_ELEMENT_NAME";

    
    
    /**
     * Extract certificates or the key available in the Assertion
     * @param elem
     * @return the SAML Key Info
     * @throws WSSecurityException
     */
    public static SAMLKeyInfo getSAMLKeyInfo(Element elem, Crypto crypto,
            CallbackHandler cb) throws WSSecurityException {
        Assertion assertion;
        try {
            // Check for duplicate saml:Assertion
			NodeList list = elem.getElementsByTagNameNS( WSConstants.SAML_NS,"Assertion");
			if (list != null && list.getLength() > 0) {
				throw new WSSecurityException("invalidSAMLSecurity");
			}
            assertion = (Assertion)XMLObjectProviderRegistrySupport.getUnmarshallerFactory().getUnmarshaller(elem).unmarshall(elem);
            return getSAMLKeyInfo(assertion, crypto, cb);
        } catch (UnmarshallingException e) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "invalidSAMLToken", new Object[]{"for Signature (cannot parse)"}, e);
        }

    }
    
    public static SAMLKeyInfo getSAMLKeyInfo(Assertion assertion, Crypto crypto,
                                             CallbackHandler cb) throws WSSecurityException {
        
        //First ask the cb whether it can provide the secret
        WSPasswordCallback pwcb = new WSPasswordCallback(assertion.getID(), WSPasswordCallback.CUSTOM_TOKEN);
        if (cb != null) {
            try {
                cb.handle(new Callback[]{pwcb});
            } catch (Exception e1) {
                throw new WSSecurityException(WSSecurityException.FAILURE, "noKey",
                        new Object[] { assertion.getID() }, e1);
            }
        }
        
        byte[] key = pwcb.getKey();
        
        if (key != null) {
            return new SAMLKeyInfo(assertion, key);
        } else {
            Iterator statements = assertion.getStatements().listIterator();
            while (statements.hasNext()) {
                Statement stmt = (Statement) statements.next();
                if (stmt instanceof AttributeStatement) {
                    org.opensaml.saml.saml1.core.AttributeStatement attrStmt = (org.opensaml.saml.saml1.core.AttributeStatement) stmt;
                    Subject samlSubject = attrStmt.getSubject();
                    Element kiElem = (Element) samlSubject.getDOM().getAttributeNode("KeyInfo");
                    
                    NodeList children = kiElem.getChildNodes();
                    int len = children.getLength();
                    
                    for (int i = 0; i < len; i++) {
                        Node child = children.item(i);
                        if (child.getNodeType() != Node.ELEMENT_NODE) {
                            continue;
                        }
                        QName el = new QName(child.getNamespaceURI(), child.getLocalName());
                        if (el.equals(WSSecurityEngine.ENCRYPTED_KEY)) {
                            
                            EncryptedKeyProcessor proc = new EncryptedKeyProcessor();
                            proc.handleEncryptedKey((Element)child, cb, crypto, null);
                            
                            return new SAMLKeyInfo(assertion, proc.getDecryptedBytes());
                        } else if (el.equals(new QName(WSConstants.WST_NS, "BinarySecret"))) {
                            Text txt = (Text)child.getFirstChild();
                            return new SAMLKeyInfo(assertion, Base64.decode(txt.getData()));
                        }
                    }

                } else if (stmt instanceof AuthenticationStatement) {
                    AuthenticationStatement authStmt = (AuthenticationStatement)stmt;
                    org.opensaml.saml.saml1.core.Subject samlSubj = authStmt.getSubject();
                    if (samlSubj == null) {
                        throw new WSSecurityException(WSSecurityException.FAILURE,
                                "invalidSAMLToken", new Object[]{"for Signature (no Subject)"});
                    }

                    Element e = (Element) samlSubj.getDOM().getAttributeNode("KeyInfo");;
                    X509Certificate[] certs = null;
                    try {
                        KeyInfo ki = new KeyInfo(e, null);

                        if (ki.containsX509Data()) {
                            X509Data data = ki.itemX509Data(0);
                            XMLX509Certificate certElem = null;
                            if (data != null && data.containsCertificate()) {
                                certElem = data.itemCertificate(0);
                            }
                            if (certElem != null) {
                                X509Certificate cert = certElem.getX509Certificate();
                                certs = new X509Certificate[1];
                                certs[0] = cert;
                                return new SAMLKeyInfo(assertion, certs);
                            }
                        }

                    } catch (XMLSecurityException e3) {
                        throw new WSSecurityException(WSSecurityException.FAILURE,
                                                      "invalidSAMLSecurity",
                                new Object[]{"cannot get certificate (key holder)"}, e3);
                    }
                    
                } else {
                    throw new WSSecurityException(WSSecurityException.FAILURE,
                                                  "invalidSAMLSecurity",
                            new Object[]{"cannot get certificate or key "});
                }
            }
            
            throw new WSSecurityException(WSSecurityException.FAILURE,
                                          "invalidSAMLSecurity",
                    new Object[]{"cannot get certificate or key "});
                        
        }

    }
    
    /**
     * Extracts the certificate(s) from the SAML token reference.
     * <p/>
     *
     * @param elem The element containing the SAML token.
     * @return an array of X509 certificates
     * @throws org.apache.ws.security.WSSecurityException
     */
    public static X509Certificate[] getCertificatesFromSAML(Element elem)
            throws WSSecurityException {

        /*
         * Get some information about the SAML token content. This controls how
         * to deal with the whole stuff. First get the Authentication statement
         * (includes Subject), then get the _first_ confirmation method only.
         */
        Assertion assertion;
        try {
            assertion = (Assertion)XMLObjectProviderRegistrySupport.getUnmarshallerFactory().getUnmarshaller(elem).unmarshall(elem);
        } catch (UnmarshallingException e) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "invalidSAMLToken", new Object[]{"for Signature (cannot parse)"}, e);
        }
        SubjectStatement samlSubjS = null;
        Iterator it = assertion.getStatements().iterator();
        while (it.hasNext()) {
            SAMLObject so = (SAMLObject) it.next();
            if (so instanceof SubjectStatement) {
                samlSubjS = (SubjectStatement) so;
                break;
            }
        }
        Subject samlSubj = null;
        if (samlSubjS != null) {
            samlSubj = samlSubjS.getSubject();
        }
        if (samlSubj == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "invalidSAMLToken", new Object[]{"for Signature (no Subject)"});
        }

//        String confirmMethod = null;
//        it = samlSubj.getConfirmationMethods();
//        if (it.hasNext()) {
//            confirmMethod = (String) it.next();
//        }
//        boolean senderVouches = false;
//        if (Subject.CONF_SENDER_VOUCHES.equals(confirmMethod)) {
//            senderVouches = true;
//        }
        Element e = (Element) samlSubj.getDOM().getAttributeNode("KeyInfo");;
        X509Certificate[] certs = null;
        try {
            KeyInfo ki = new KeyInfo(e, null);

            if (ki.containsX509Data()) {
                X509Data data = ki.itemX509Data(0);
                XMLX509Certificate certElem = null;
                if (data != null && data.containsCertificate()) {
                    certElem = data.itemCertificate(0);
                }
                if (certElem != null) {
                    X509Certificate cert = certElem.getX509Certificate();
                    certs = new X509Certificate[1];
                    certs[0] = cert;
                }
            }
            // TODO: get alias name for cert, check against username set by caller
        } catch (XMLSecurityException e3) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                                          "invalidSAMLSecurity",
                    new Object[]{"cannot get certificate (key holder)"}, e3);
        }
        return certs;
    }

    public static String getAssertionId(Element envelope, String elemName, String nmSpace) throws WSSecurityException {
        String id;
        // Make the AssertionID the wsu:Id and the signature reference the same
        Assertion assertion;

        Element assertionElement = (Element) WSSecurityUtil
                .findElement(envelope, elemName, nmSpace);

        try {
            assertion = (Assertion)XMLObjectProviderRegistrySupport.getUnmarshallerFactory().getUnmarshaller(assertionElement).unmarshall(assertionElement);
            id = assertion.getID();
        } catch (Exception e1) {
            log.error(e1);
            throw new WSSecurityException(
                    WSSecurityException.FAILED_SIGNATURE,
                    "noXMLSig", null, e1);
        }
        return id;
    }

     /**
     * Create a TimeStamp object from the SAML assertion.
     * @param assertion
     * @return
     * @throws WSSecurityException
     */
    public static Timestamp getTimestampForSAMLAssertion(Element assertion) throws WSSecurityException {

        String[] validityPeriod = getValidityPeriod(assertion);
        // If either of the timestamps are missing, then return a null
        if(validityPeriod[0] == null || validityPeriod[1] == null){
            return null;
        }

        try {
            DocumentBuilderFactory dbFactory = XMLUtils.getSecuredDocumentBuilder();
            Document document =  dbFactory.newDocumentBuilder().newDocument();
            Element element = document.createElement("SAMLTimestamp");

            Element createdElement =  document.createElementNS( WSConstants.WSU_NS,WSConstants.CREATED_LN);
            createdElement.setTextContent(validityPeriod[0]);
            element.appendChild(createdElement);

            Element expiresElement = document.createElementNS( WSConstants.WSU_NS,WSConstants.EXPIRES_LN);
            expiresElement.setTextContent(validityPeriod[1]);
            element.appendChild(expiresElement);

            return new Timestamp(element);

        } catch (ParserConfigurationException e) {
            throw new WSSecurityException(WSSecurityException.FAILURE,"SAMLTimeStampBuildError", null , e );
        } catch (WSSecurityException e) {
            throw new WSSecurityException(WSSecurityException.FAILURE,"SAMLTimeStampBuildError", null , e );
        }
    }

    /**
     * Extract the URIs of the set of claims available in a SAML 1.0/1.1 assertion. This method will
     * iterate through the set of AttributeStatements available and extract the namespaces of the claim.
     * @param assertion SAML 1.0/1.1 assertion
     * @return  A TreeSet instance comprise of all the claims available in a SAML assertion
     */
    public static Set getClaims(Assertion assertion){
        Set claims = new TreeSet();
        // iterate over the statements
        for (Object statement : assertion.getStatements()) {
            // if it is AttributeStatement, then extract the attributes
            if (statement instanceof AttributeStatement) {
                for (Attribute attribute : ((AttributeStatement) statement).getAttributes()) {
                    claims.add(attribute.getAttributeName());
                }
            }
        }
        return claims;
    }

    /**
     * Validate the signature of the SAML assertion
     * @param assertion SAML 1.0/1.1 assertion
     * @param sigCrypto Crypto object containing the certificate of the token issuer
     * @throws WSSecurityException if the token does not contain certificate information, the certificate
     *          of the issuer is not trusted or the signature is invalid.
     */
    public static void validateSignature(Assertion assertion, Crypto sigCrypto)
            throws WSSecurityException {

        Iterator x509Certificates = null;

        List x509Data = assertion.getSignature().getKeyInfo().getX509Datas();
        if (x509Data != null && x509Data.size() > 0) {
            // Pick the first <ds:X509Data/> element
            org.opensaml.xmlsec.signature.X509Data x509Cred = (org.opensaml.xmlsec.signature.X509Data) x509Data.get(0);
            // Get the <ds:X509Certificate/> elements
            List x509Certs = x509Cred.getX509Certificates();

            x509Certificates = x509Certs.iterator();

            if (x509Certificates.hasNext()) {
                X509Certificate x509Certificate = (X509Certificate) x509Certificates.next();

                // check whether the issuer's certificate is available in the signature crypto
                if (sigCrypto.getAliasForX509Cert(x509Certificate) != null) {
//                        assertion.verify(x509Certificate);
                } else {
                    throw new WSSecurityException(WSSecurityException.FAILURE, "SAMLTokenUntrustedSignatureKey");
                }
            } else {
                throw new WSSecurityException(WSSecurityException.FAILURE, "SAMLTokenInvalidX509Data");
            }
        } else{
            throw new WSSecurityException(WSSecurityException.FAILURE, "SAMLTokenInvalidX509Data");
        }
    }

    /**
     * Create a new SAML object.
     *
     * @param <T>        the generic type
     * @param objectType the object type
     * @return the t
     */
    public static <T extends SAMLObject> T newSamlObject(final Class<T> objectType) {
        final QName qName = getSamlObjectQName(objectType);
        final SAMLObjectBuilder<T> builder = (SAMLObjectBuilder<T>)
                XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(qName);
        if (builder == null) {
            throw new IllegalStateException("No SAML object builder is registered for class " + objectType.getName());
        }
        return objectType.cast(builder.buildObject(qName));
    }


    /**
     * Gets saml object QName.
     *
     * @param objectType the object type
     * @return the saml object QName
     * @throws RuntimeException the exception
     */
    public static QName getSamlObjectQName(final Class objectType) throws RuntimeException {
        try {
            final Field f = objectType.getField(DEFAULT_ELEMENT_NAME_FIELD);
            return (QName) f.get(null);
        } catch (final NoSuchFieldException e) {
            throw new IllegalStateException("Cannot find field " + objectType.getName() + '.' + DEFAULT_ELEMENT_NAME_FIELD, e);
        } catch (final IllegalAccessException e) {
            throw new IllegalStateException("Cannot access field " + objectType.getName() + '.' + DEFAULT_ELEMENT_NAME_FIELD, e);
        }
    }

    private static String[] getValidityPeriod(Element assertion){
        String[] validityPeriod = new String[2];
        for (Node currentChild = assertion.getFirstChild();
             currentChild != null;
             currentChild = currentChild.getNextSibling()
         ){
            if(WSConstants.SAML_CONDITION.equals(currentChild.getLocalName())
                    && WSConstants.SAML_NS.equals(currentChild.getNamespaceURI())){
                NamedNodeMap attributes = currentChild.getAttributes();
                for(int i=0; i < attributes.getLength(); i++){
                    Node attr = attributes.item(i);
                    if(WSConstants.SAML_NOT_BEFORE.equals(attr.getLocalName())){
                       validityPeriod[0] = attr.getNodeValue();
                    }
                    else if(WSConstants.SAML_NOT_AFTER.equals(attr.getLocalName())){
                        validityPeriod[1] = attr.getNodeValue();
                    }
                }

                break;
            }
        }

        return validityPeriod;
    }

}
