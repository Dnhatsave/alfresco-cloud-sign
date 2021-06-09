/**
 * 
 */
package org.alfresco.plugin.digitalSigning.utils;

import org.alfresco.error.AlfrescoRuntimeException;
import org.alfresco.plugin.digitalSigning.dto.DigitalSigningDTO;

/**
 * Signing utils class.
 * 
 * @author Emmanuel ROUX
 */
public class SigningUtils {

	/**
	 * Validate DigitalSigningDTO object.
	 * 
	 * @param digitalSigningDTO object to validate
	 */
	public static void validateSignInfo (final DigitalSigningDTO digitalSigningDTO) {
		if (digitalSigningDTO != null) {
			if (digitalSigningDTO.getKeyFile() == null) {
				throw new AlfrescoRuntimeException("key file parameter is required.");
			}
			
			if (digitalSigningDTO.getKeyPassword() == null) {
				throw new AlfrescoRuntimeException("A senha é de carracter obrigatória.");
			}
			
			/*
			if (digitalSigningDTO.getDestinationFolder() == null) {
				throw new AlfrescoRuntimeException("destination folder parameter is required.");
			}
			*/
			
			if (digitalSigningDTO.getFilesToSign() == null && digitalSigningDTO.getFilesToSign().size() == 0) {
				throw new AlfrescoRuntimeException("document(s) to sign parameter is required.");
			}
			
			
		}
	}
}
