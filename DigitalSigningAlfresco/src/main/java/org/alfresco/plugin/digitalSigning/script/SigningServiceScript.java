/**
 * 
 */
package org.alfresco.plugin.digitalSigning.script;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;

import org.alfresco.error.AlfrescoRuntimeException;
import org.alfresco.model.ContentModel;
import org.alfresco.plugin.digitalSigning.dto.DigitalSigningDTO;
import org.alfresco.plugin.digitalSigning.dto.VerifyResultDTO;
import org.alfresco.plugin.digitalSigning.dto.VerifyingDTO;
import org.alfresco.plugin.digitalSigning.model.SigningConstants;
import org.alfresco.plugin.digitalSigning.model.SigningModel;
import org.alfresco.plugin.digitalSigning.service.SigningService;
import org.alfresco.plugin.digitalSigning.utils.SigningUtils;
import org.alfresco.repo.jscript.BaseScopableProcessorExtension;
import org.alfresco.service.cmr.repository.ChildAssociationRef;
import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.repository.NodeService;
import org.alfresco.service.cmr.security.AuthenticationService;
import org.alfresco.service.cmr.security.PersonService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.mozilla.javascript.ConsString;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.NativeJavaObject;
import org.mozilla.javascript.NativeObject;
import org.mozilla.javascript.Scriptable;

/**
 * Sign script service.
 * 
 * @author Emmanuel ROUX
 */
public class SigningServiceScript extends BaseScopableProcessorExtension {
	
	/**
	 * Logger.
	 */
	private final Log log = LogFactory.getLog(SigningServiceScript.class);

	/**
	 * Sign service.
	 */
	private SigningService digitalSigningService;
	
	/**
	 * Authentication service.
	 */
	private AuthenticationService authenticationService;
	
	/**
	 * Person service.
	 */
	private PersonService personService;
	
	/**
	 * Node service.
	 */
	private NodeService nodeService;
	
	/**
	 * Sign a document.
	 * 
	 * @param parameters sign parameters
	 */
	public void sign(final NativeObject parameters) {
		String privateKeyStr = null;
		if (parameters.get("keyFile", null) instanceof String) {
			privateKeyStr = (String) parameters.get("keyFile", null);
		}
		String keyPassword = null;
		if (parameters.get("keyPassword", null) instanceof String) {
			keyPassword = (String) parameters.get("keyPassword", null);
		}
		String filesToSignStr = null;
		if (parameters.get("document", null) instanceof String) {
			filesToSignStr = (String) parameters.get("document", null);
		}
		if (parameters.get("document", null) instanceof ConsString) {
			filesToSignStr = ((ConsString) parameters.get("document", null)).toString();
		}
		if (parameters.get("document", null) instanceof NativeJavaObject) {
			filesToSignStr = ((NativeJavaObject)parameters.get("document", null)).unwrap().toString();
		}
		String destinationFolderStr = null;
		if (parameters.get("destination", null) instanceof String) {
			destinationFolderStr = (String) parameters.get("destination", null);
		}
				
		final DigitalSigningDTO signingDTO = new DigitalSigningDTO();
		
		if (privateKeyStr != null) {
			try {
				final NodeRef privateKey = new NodeRef(privateKeyStr);
				if (privateKey != null) {
					signingDTO.setKeyFile(privateKey);
				}
			} catch (Exception e) {
				log.error("keyFile must be a valid nodeRef.");
				throw new AlfrescoRuntimeException("keyFile must be a valid nodeRef.");
			}
		} else {
			// Get current user key
			final String currentUser = authenticationService.getCurrentUserName();
			final NodeRef currentUserNodeRef = personService.getPerson(currentUser);
			if (currentUserNodeRef != null) {
				final NodeRef currentUserHomeFolder = (NodeRef) nodeService.getProperty(currentUserNodeRef, ContentModel.PROP_HOMEFOLDER);
				if (currentUserHomeFolder != null) {
					final NodeRef signingFolderNodeRef = nodeService.getChildByName(currentUserHomeFolder, ContentModel.ASSOC_CONTAINS, SigningConstants.KEY_FOLDER);
					if (signingFolderNodeRef != null) {
						final List<ChildAssociationRef> children = nodeService.getChildAssocs(signingFolderNodeRef);
						if (children != null && children.size() > 0) {
							final Iterator<ChildAssociationRef> itChildren = children.iterator();
							boolean foundKey = false;
							while (itChildren.hasNext() && !foundKey) {
								final ChildAssociationRef childAssoc = itChildren.next();
								final NodeRef child = childAssoc.getChildRef();
								if (nodeService.hasAspect(child, SigningModel.ASPECT_KEY)) {
									signingDTO.setKeyFile(child);
									foundKey = true;
								}
							}
							if (!foundKey) {
								log.error("No key file uploaded for user " + currentUser + ".");
								throw new AlfrescoRuntimeException("No key file uploaded for user " + currentUser + ".");
							}
						} else {
							log.error("No key file uploaded for user " + currentUser + ".");
							throw new AlfrescoRuntimeException("No key file uploaded for user " + currentUser + ".");
						}
					} else {
						log.error("No key file uploaded for user " + currentUser + ".");
						throw new AlfrescoRuntimeException("No key file uploaded for user " + currentUser + ".");
					}
				} else {
					log.error("User '" + currentUser + "' have no home folder.");
					throw new AlfrescoRuntimeException("User '" + currentUser + "' have no home folder.");
				}
			}
		}
		if (keyPassword != null) {
			signingDTO.setKeyPassword(keyPassword);
		} else {
			log.error("Insira o pin da Assinatura Digital.");
			throw new AlfrescoRuntimeException("Insira o pin da Assinatura Digital.");
		}
		if (destinationFolderStr != null && destinationFolderStr.compareTo("") != 0) {
			try {
				final NodeRef destinationFolder = new NodeRef(destinationFolderStr);
				if (destinationFolder != null) {
					signingDTO.setDestinationFolder(destinationFolder);
				}
			} catch (Exception e) {
				log.error("destination must be a valid nodeRef.");
				throw new AlfrescoRuntimeException("destination must be a valid nodeRef.");
			}
		} else {
			signingDTO.setDestinationFolder(null);
			//log.error("destination parameter is required.");
			//throw new AlfrescoRuntimeException("destination parameter is required.");
		}
		
		
		// Get file(s) to sign
		if (filesToSignStr != null) {
			final String[] nodeRefs = filesToSignStr.split(",");
			final List<NodeRef> nodeRefsToSign = new ArrayList<NodeRef>();
			signingDTO.setFilesToSign(nodeRefsToSign);
			
			for (int i = 0; i < nodeRefs.length ; i++) {
				final String nodeRef = nodeRefs[i];
				try {
					final NodeRef fileToSign = new NodeRef(nodeRef);
					if (fileToSign != null) {
						signingDTO.getFilesToSign().add(fileToSign);
					}
				} catch (Exception e) {
					log.error("document must be a valid nodeRef.");
					throw new AlfrescoRuntimeException("document must be a valid nodeRef : " + nodeRef);
				}
			}
		} else {
			log.error("document(s) parameter is required.");
			throw new AlfrescoRuntimeException("document parameter is required.");
		}
		
		// Validate DTO
		SigningUtils.validateSignInfo(signingDTO);
		
		digitalSigningService.sign(signingDTO);
	}
	
	/**
	 * Verify sign.
	 * 
	 * @param parameters parameter
	 * @return verify result
	 */
	public Scriptable verify(final NativeObject parameters) {
		final VerifyingDTO verifyingDTO = new VerifyingDTO();
		
		String privateKeyStr = null;
		if (parameters.get("keyFile", null) instanceof String) {
			privateKeyStr = (String) parameters.get("keyFile", null);
		}
		String keyPassword = null;
		if (parameters.get("keyPassword", null) instanceof String) {
			keyPassword = (String) parameters.get("keyPassword", null);
		}
		String fileToVerifyStr = null;
		if (parameters.get("document", null) instanceof String) {
			fileToVerifyStr = (String) parameters.get("document", null);
		}
		
		if (privateKeyStr != null) {
			try {
				final NodeRef privateKey = new NodeRef(privateKeyStr);
				if (privateKey != null) {
					verifyingDTO.setKeyFile(privateKey);
				}
			} catch (Exception e) {
				log.error("keyFile must be a valid nodeRef.");
				throw new AlfrescoRuntimeException("keyFile must be a valid nodeRef.");
			}
		} else {
			// Get current user key
			final String currentUser = authenticationService.getCurrentUserName();
			final NodeRef currentUserNodeRef = personService.getPerson(currentUser);
			if (currentUserNodeRef != null) {
				final NodeRef currentUserHomeFolder = (NodeRef) nodeService.getProperty(currentUserNodeRef, ContentModel.PROP_HOMEFOLDER);
				if (currentUserHomeFolder != null) {
					final NodeRef signingFolderNodeRef = nodeService.getChildByName(currentUserHomeFolder, ContentModel.ASSOC_CONTAINS, SigningConstants.KEY_FOLDER);
					if (signingFolderNodeRef != null) {
						final List<ChildAssociationRef> children = nodeService.getChildAssocs(signingFolderNodeRef);
						if (children != null && children.size() > 0) {
							final Iterator<ChildAssociationRef> itChildren = children.iterator();
							boolean foundKey = false;
							while (itChildren.hasNext() && !foundKey) {
								final ChildAssociationRef childAssoc = itChildren.next();
								final NodeRef child = childAssoc.getChildRef();
								if (nodeService.hasAspect(child, SigningModel.ASPECT_KEY)) {
									verifyingDTO.setKeyFile(child);
									foundKey = true;
								}
							}
							if (!foundKey) {
								log.error("No key file uploaded for user " + currentUser + ".");
								throw new AlfrescoRuntimeException("No key file uploaded for user " + currentUser + ".");
							}
						} else {
							log.error("No key file uploaded for user " + currentUser + ".");
							throw new AlfrescoRuntimeException("No key file uploaded for user " + currentUser + ".");
						}
					} else {
						log.error("No key file uploaded for user " + currentUser + ".");
						throw new AlfrescoRuntimeException("No key file uploaded for user " + currentUser + ".");
					}
				} else {
					log.error("User '" + currentUser + "' have no home folder.");
					throw new AlfrescoRuntimeException("User '" + currentUser + "' have no home folder.");
				}
			}
		}
		if (keyPassword != null) {
			verifyingDTO.setKeyPassword(keyPassword);
		} else {
			log.error("Insira o pin da Assinatura Digital.");
			throw new AlfrescoRuntimeException("Insira o pin da Assinatura Digital.");
		}
		if (fileToVerifyStr != null) {
			try {
				final NodeRef fileToVerify = new NodeRef(fileToVerifyStr);
				if (fileToVerify != null) {
					verifyingDTO.setFileToVerify(fileToVerify);
				}
			} catch (Exception e) {
				log.error("document must be a valid nodeRef.");
				throw new AlfrescoRuntimeException("document must be a valid nodeRef.");
			}
		} else {
			log.error("document parameter is required.");
			throw new AlfrescoRuntimeException("document parameter is required.");
		}
		
		final List<VerifyResultDTO> result = digitalSigningService.verifySign(verifyingDTO);
		
		return Context.getCurrentContext().newArray(getScope(), result.toArray());
	}

	/**
	 * Get int value form serialized object.
	 * 
	 * @param val serialized object
	 * @return int value of serialized object
	 */
	protected int getInteger(Serializable val) {
        if(val == null) { 
        	return 0;
        }
        try {
        	return Integer.parseInt(val.toString());
        } catch(NumberFormatException nfe) {
        	return 0;
        }
    }

	/**
	 * @param signService the signService to set
	 */
	public final void setDigitalSigningService(SigningService digitalSigningService) {
		this.digitalSigningService = digitalSigningService;
	}


	/**
	 * @param authenticationService the authenticationService to set
	 */
	public final void setAuthenticationService(
			AuthenticationService authenticationService) {
		this.authenticationService = authenticationService;
	}


	/**
	 * @param personService the personService to set
	 */
	public final void setPersonService(PersonService personService) {
		this.personService = personService;
	}


	/**
	 * @param nodeService the nodeService to set
	 */
	public final void setNodeService(NodeService nodeService) {
		this.nodeService = nodeService;
	}
	
}
