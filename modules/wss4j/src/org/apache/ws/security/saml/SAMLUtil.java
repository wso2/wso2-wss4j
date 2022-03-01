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
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.util.WSSecurityUtil;

import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.saml1.core.Assertion;

import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import java.lang.reflect.Field;

/**
 * Utility methods for SAML stuff
 */
public class SAMLUtil {
    private static final Log log = LogFactory.getLog(SAMLUtil.class.getName());

    public static final String DEFAULT_ELEMENT_NAME_FIELD = "DEFAULT_ELEMENT_NAME";

    public static String getAssertionId(Element envelope, String elemName, String nmSpace) throws WSSecurityException {
        String id;
        // Make the AssertionID the wsu:Id and the signature reference the same
        Assertion assertion;

        Element assertionElement = (Element) WSSecurityUtil
                .findElement(envelope, elemName, nmSpace);

        try {
            assertion = (Assertion)XMLObjectProviderRegistrySupport.getUnmarshallerFactory().
                    getUnmarshaller(assertionElement).unmarshall(assertionElement);
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

}
