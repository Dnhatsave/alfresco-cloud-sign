/**
 * 
 */
package org.alfresco.plugin.digitalSigning.service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;


import org.alfresco.error.AlfrescoRuntimeException;
import org.alfresco.model.ContentModel;
import org.alfresco.plugin.digitalSigning.dto.DigitalSigningDTO;
import org.alfresco.plugin.digitalSigning.dto.VerifyResultDTO;
import org.alfresco.plugin.digitalSigning.dto.VerifyingDTO;
import org.alfresco.plugin.digitalSigning.model.SigningConstants;
import org.alfresco.plugin.digitalSigning.model.SigningModel;
import org.alfresco.plugin.digitalSigning.utils.CryptUtils;
import org.alfresco.repo.content.MimetypeMap;
import org.alfresco.repo.content.filestore.FileContentReader;
import org.alfresco.repo.content.filestore.FileContentWriter;
import org.alfresco.repo.content.transform.ContentTransformer;
import org.alfresco.repo.content.transform.ContentTransformerRegistry;
import org.alfresco.repo.node.encryption.MetadataEncryptor;
import org.alfresco.repo.security.authentication.AuthenticationUtil;
import org.alfresco.service.cmr.dictionary.DictionaryService;
import org.alfresco.service.cmr.model.FileFolderService;
import org.alfresco.service.cmr.model.FileInfo;
import org.alfresco.service.cmr.repository.ContentIOException;
import org.alfresco.service.cmr.repository.ContentReader;
import org.alfresco.service.cmr.repository.ContentService;
import org.alfresco.service.cmr.repository.ContentWriter;
import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.repository.NodeService;
import org.alfresco.service.cmr.repository.TransformationOptions;
import org.alfresco.service.namespace.QName;
import org.alfresco.util.TempFileProvider;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.pdfbox.examples.pdfa.CreatePDFA;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.common.PDMetadata;
import org.apache.pdfbox.pdmodel.graphics.color.PDOutputIntent;
import org.apache.xmpbox.XMPMetadata;
import org.apache.xmpbox.schema.PDFAIdentificationSchema;
import org.apache.xmpbox.type.BadFieldValueException;
import org.apache.xmpbox.xml.XmpSerializer;
//import org.bouncycastle.asn1.DERObjectIdentifier; updated for recent package

import org.bouncycastle.jce.provider.BouncyCastleProvider;


import com.itextpdf.text.pdf.AcroFields;
//import com.itextpdf.text.pdf.PdfPKCS7;
import com.itextpdf.text.pdf.security.PdfPKCS7;


import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Element;
import com.itextpdf.text.Phrase;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.ColumnText;
import com.itextpdf.text.pdf.PdfContentByte;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfStamper;

import com.itextpdf.text.pdf.BarcodeQRCode;






/**
 * Sign service for Alfresco
 * 
 * @author Emmanuel ROUX
 */
public class SigningService {
	
	/**
	 * Logger.
	 */
	private final Log log = LogFactory.getLog(SigningService.class);
	

	/**
	 * Node service.
	 */
	private NodeService nodeService;
	
	/**
	 * Dictionary service.
	 */
	private DictionaryService dictionaryService;
	
	/**
	 * Content service.
	 */
	private ContentService contentService;
	
	/**
	 * File folder service.
	 */
	private FileFolderService fileFolderService;
	
	/**
	 * Content Transformer registry.
	 */
	private ContentTransformerRegistry contentTransformerRegistry;
	
	/**
	 * Metadata encryptor.
	 */
	private MetadataEncryptor metadataEncryptor;
	
	/**
	 * PADES Signing.
	 * 
	 * @param nodeRefToSign NodeRef to sign
	 * @param signingDTO SigningDTO object
	 * @param alfTempDir Alfresco temporary directoru
	 * @param alias Sign Alias to use
	 * @param ks KeyStore
	 * @param key Key
	 * @param chain Chain
	 * @param userLocale user locale
	 * @return null or an error during signing process
	 */
	private AlfrescoRuntimeException signPDFFile(final NodeRef nodeRefToSign, final DigitalSigningDTO signingDTO, final File alfTempDir, final String alias, final KeyStore ks, final PrivateKey key, final Certificate[] chain) {
		final String fileNameToSign = fileFolderService.getFileInfo(nodeRefToSign).getName();
		
		File fileConverted = null;
		File tempDir = null;
		try {
			ContentReader fileToSignContentReader = getReader(nodeRefToSign);
			
			if (fileToSignContentReader != null) {
				String newName = null;
				
				// Check if document is PDF or transform it
				if (!MimetypeMap.MIMETYPE_PDF.equals(fileToSignContentReader.getMimetype())) {
					// Transform document in PDF document
					final ContentTransformer tranformer = contentTransformerRegistry.getTransformer(fileToSignContentReader.getMimetype(), fileToSignContentReader.getSize(), MimetypeMap.MIMETYPE_PDF, new TransformationOptions());
					
					if (tranformer != null) {
						
						tempDir = new File(alfTempDir.getPath() + File.separatorChar + nodeRefToSign.getId());
				        if (tempDir != null) {
							tempDir.mkdir();
					        fileConverted = new File(tempDir, fileNameToSign + "_" + System.currentTimeMillis() + ".pdf");
							if (fileConverted != null) {
						        final ContentWriter newDoc = new FileContentWriter(fileConverted);
						        if (newDoc != null) {
									newDoc.setMimetype(MimetypeMap.MIMETYPE_PDF);
									final TransformationOptions transformationOptions = null;
									tranformer.transform(fileToSignContentReader, newDoc, transformationOptions);
									fileToSignContentReader = new FileContentReader(fileConverted);
									
									final String originalName = (String) nodeService.getProperty(nodeRefToSign, ContentModel.PROP_NAME);
									
									if (originalName.lastIndexOf(".") == -1) {
										newName = originalName + ".pdf";
									} else {
										newName = originalName.substring(0, originalName.lastIndexOf(".")) + ".pdf";
									}
						        }
							}
				        }
					} else {
						log.error("[" + fileNameToSign + "] No suitable converter found to convert the document in PDF.");
						return new AlfrescoRuntimeException("[" + fileNameToSign + "] No suitable converter found to convert the document in PDF.");
					}
				}

				PdfReader reader = null;
				if (nodeRefToSign != null) {
			        tempDir = new File(alfTempDir.getPath() + File.separatorChar + nodeRefToSign.getId());
			        if (tempDir != null) {
				        tempDir.mkdir();
				        final File file = new File(tempDir, fileNameToSign);
				        
				        if (file != null) {
					        final FileOutputStream fout = new FileOutputStream(file);
					        //final PdfStamper stp = PdfStamper.createSignature(reader, fout, '\0');
					        
					        final File tempFile = new File(tempDir, fileNameToSign + "_tmp");
					        // Use parameter "true" to allow multiple signature on the PDF
					        //final PdfStamper stp = PdfStamper.createSignature(reader, fout, '\0', tempFile, true);
							

							//TODO atualizar a marca de agua na segunda assinatura


							//reader = new PdfReader(fileToSignContentReader.getContentInputStream());


							reader = new PdfReader(fileToSignContentReader.getContentInputStream());
							
							
							final PdfStamper stamper = new PdfStamper(reader, fout);
							//final PdfStamper stp = PdfStamper.createSignature(reader, fout, '\0', tempFile, true);

							

							
							final SimpleDateFormat df = new SimpleDateFormat("dd MMM yyyy HH:mm");

					        if (reader != null) {
								PdfContentByte canvas;
        						Rectangle pageSize;
								float x, y;
								for (int p = 1; p <= reader.getNumberOfPages(); p++) {	
									pageSize = reader.getPageSize(p);
					
									// left of the page
									x = pageSize.getRight();
									// middle of the height
									y = (pageSize.getTop() + pageSize.getBottom()) / 2;
									// getting the canvas covering the existing content
									canvas = stamper.getOverContent(p);
									// adding some lines to the left
									ColumnText.showTextAligned(canvas, Element.ALIGN_CENTER,
										new Phrase("Documento Assinado Digitalmente em https://www.cedsif.gov.mz/sgd/"),
										x - 18, y, 90);
									 ColumnText.showTextAligned(canvas, Element.ALIGN_CENTER,
									 	new Phrase("Assinado por " + AuthenticationUtil.getRunAsUser() + " aos " + df.format(new Date())),
									 	x - 1, y, 90);

								}
					
								stamper.close();

								NodeRef destinationNode = null;
									NodeRef originalDoc = null;
									boolean addAsNewVersion = false;
									if (signingDTO.getDestinationFolder() == null) {
										destinationNode = nodeRefToSign;
										nodeService.addAspect(destinationNode, ContentModel.ASPECT_VERSIONABLE, null);
										addAsNewVersion = true;
									} else {
										originalDoc = nodeRefToSign;
										destinationNode = createDestinationNode(file.getName(), signingDTO.getDestinationFolder(), nodeRefToSign);
									}
								
									if (destinationNode != null) {
							            
						            	final ContentWriter writer = contentService.getWriter(destinationNode, ContentModel.PROP_CONTENT, true);
							            if (writer != null) {
								            writer.setEncoding(fileToSignContentReader.getEncoding());
								            writer.setMimetype("application/pdf");
								            writer.putContent(file);
								            file.delete();
								            
								            if (fileConverted != null) {
								            	fileConverted.delete();
								            }
							            
								            nodeService.addAspect(destinationNode, SigningModel.ASPECT_SIGNED, new HashMap<QName, Serializable>());
								            nodeService.setProperty(destinationNode, SigningModel.PROP_SIGNATUREDATE, new java.util.Date());
								            nodeService.setProperty(destinationNode, SigningModel.PROP_SIGNEDBY, AuthenticationUtil.getRunAsUser());
								            
								            if (newName != null) {
								            	nodeService.setProperty(destinationNode, ContentModel.PROP_NAME, newName);
								            }
								            								            
								            if (!addAsNewVersion) {
									            if (!nodeService.hasAspect(originalDoc, SigningModel.ASPECT_ORIGINAL_DOC)) {
									            	nodeService.addAspect(originalDoc, SigningModel.ASPECT_ORIGINAL_DOC, new HashMap<QName, Serializable>());
									            }
									            nodeService.createAssociation(originalDoc, destinationNode, SigningModel.PROP_RELATED_DOC);
								            }
								            
							            }
						            } else {
									log.error("[" + fileNameToSign + "] Destination node is not a valid NodeRef.");
									return new AlfrescoRuntimeException("[" + fileNameToSign + "] Destination node is not a valid NodeRef.");
								}
							} else {
					        	log.error("[" + fileNameToSign + "] Unable to create PDF signature.");
					        	return new AlfrescoRuntimeException("[" + fileNameToSign + "] Unable to create PDF signature.");
							}
				        }
			        }
				 } else {
					log.error("[" + fileNameToSign + "] Unable to get document to sign content.");
					return new AlfrescoRuntimeException("[" + fileNameToSign + "] Unable to get document to sign content.");
				}
				
				return null;
				
			} else {
				log.error("[" + fileNameToSign + "] The document has no content.");
				return new AlfrescoRuntimeException("[" + fileNameToSign + "] The document has no content.");
			}
		} catch (ContentIOException e) {
			log.error("[" + fileNameToSign + "] " + e);
			return new AlfrescoRuntimeException("[" + fileNameToSign + "] " + e.getMessage(), e);
		} catch (IOException e) {
			log.error("[" + fileNameToSign + "] " + e);
			return new AlfrescoRuntimeException("[" + fileNameToSign + "] " + e.getMessage(), e);
		} catch (DocumentException e) {
			log.error("[" + fileNameToSign + "] " + e);
			return new AlfrescoRuntimeException("[" + fileNameToSign + "] " + e.getMessage(), e);
		//} catch (GeneralSecurityException e) {
		//	log.error("[" + fileNameToSign + "] " + e);
		//	return new AlfrescoRuntimeException("[" + fileNameToSign + "] " + e.getMessage(), e);
		} finally {
            if (tempDir != null) {
                try {
                    tempDir.delete();
                } catch (Exception ex) {
                	log.error("[" + fileNameToSign + "] " + ex);
                	return new AlfrescoRuntimeException("[" + fileNameToSign + "] " + ex.getMessage(), ex);
                }
            }
        }
	}
	
	/**
	 * XADES signing.
	 * 
	 * @param nodeRefToSign NodeRef to sign
	 * @param signingDTO SigningDTO object
	 * @param alfTempDir Alfresco temporary directoru
	 * @param alias Sign Alias to use
	 * @param ks KeyStore
	 * @param key Key
	 * @param chain Chain
	 * @return null or an error during signing process
	 */

	/**
	 * Sign file.
	 * 
	 * @param signingDTO sign informations
	 * @param pdfSignedFile signed pdf returned
	 * 
	 */
	public void sign(final DigitalSigningDTO signingDTO) {
		if (signingDTO != null) {
			
			try {
				Security.addProvider(new BouncyCastleProvider());
				final File alfTempDir = TempFileProvider.getTempDir();
				
				if (alfTempDir != null) {
					final String keyType = (String) nodeService.getProperty(signingDTO.getKeyFile(), SigningModel.PROP_KEYTYPE);
					
					if (SigningConstants.KEY_TYPE_X509.equals(keyType)) {
						// Sign the file
						final KeyStore ks = KeyStore.getInstance("pkcs12");
						final ContentReader keyContentReader = getReader(signingDTO.getKeyFile());
						
						if (keyContentReader != null && ks != null && signingDTO.getKeyPassword() != null) {
							
							final List<AlfrescoRuntimeException> errors = new ArrayList<AlfrescoRuntimeException>();
							
							// Get crypted secret key and decrypt it
							final Serializable encryptedPropertyValue = nodeService.getProperty(signingDTO.getKeyFile(), SigningModel.PROP_KEYCRYPTSECRET);
							final Serializable decryptedPropertyValue = metadataEncryptor.decrypt(SigningModel.PROP_KEYCRYPTSECRET, encryptedPropertyValue);
							
							// Decrypt key content
							InputStream decryptedKeyContent;
							try {
								decryptedKeyContent = CryptUtils.decrypt(decryptedPropertyValue.toString(), keyContentReader.getContentInputStream());
							} catch (Throwable e) {
								log.error(e);
								throw new AlfrescoRuntimeException(e.getMessage(), e);
							}
							
							ks.load(new ByteArrayInputStream(IOUtils.toByteArray(decryptedKeyContent)), signingDTO.getKeyPassword().toCharArray());
							
							final String alias = (String) nodeService.getProperty(signingDTO.getKeyFile(), SigningModel.PROP_KEYALIAS);
							
							final PrivateKey key = (PrivateKey)ks.getKey(alias, signingDTO.getKeyPassword().toCharArray());
							final Certificate[] chain = ks.getCertificateChain(alias);
							
							final Iterator<NodeRef> itFilesToSign = signingDTO.getFilesToSign().iterator();
							while (itFilesToSign.hasNext()) {
								final NodeRef nodeRefToSign = itFilesToSign.next();
								AlfrescoRuntimeException exception = null;
								final String fileToSignName = (String) nodeService.getProperty(nodeRefToSign, ContentModel.PROP_NAME);

								
								// PADES
								 if(fileToSignName.endsWith(".pdf")){
									exception = signPDFFile(nodeRefToSign, signingDTO, alfTempDir, alias, ks, key, chain);
								}
								if (exception != null) {
									// Error on the file process
									errors.add(exception);
								}
							}
						
							if (errors != null && errors.size() > 0) {
								final StringBuffer allErrors = new StringBuffer();
								final Iterator<AlfrescoRuntimeException> itErrors = errors.iterator();
								if (errors.size() > 1) {
									allErrors.append("\n");
								}
								while (itErrors.hasNext()) {
									final AlfrescoRuntimeException alfrescoRuntimeException = itErrors.next();
									allErrors.append(alfrescoRuntimeException.getMessage());
									if (itErrors.hasNext()) {
										allErrors.append("\n");
									}
								}
								throw new RuntimeException(allErrors.toString());
							}
						
						} else {
							log.error("Unable to get key content, key type or key password.");
							throw new AlfrescoRuntimeException("Unable to get key content, key type or key password.");
						}
					}
				} else {
					log.error("Unable to get temporary directory.");
					throw new AlfrescoRuntimeException("Unable to get temporary directory.");
				}
			} catch (KeyStoreException e) {
				log.error(e);
				throw new AlfrescoRuntimeException(e.getMessage(), e);
			} catch (NoSuchAlgorithmException e) {
				log.error(e);
				throw new AlfrescoRuntimeException(e.getMessage(), e);
			} catch (CertificateException e) {
				log.error(e);
				throw new AlfrescoRuntimeException(e.getMessage(), e);
			} catch (IOException e) {
				log.error(e);
				throw new AlfrescoRuntimeException(e.getMessage(), e);
			} catch (UnrecoverableKeyException e) {
				log.error(e);
				throw new AlfrescoRuntimeException(e.getMessage(), e);
			}
		} else {
			log.error("No object with signing informations.");
			throw new AlfrescoRuntimeException("No object with signing informations.");
		}
	}
	
	
	public List<VerifyResultDTO> verifySign(final VerifyingDTO verifyingDTO) {
		final List<VerifyResultDTO> result = new ArrayList<VerifyResultDTO>();
		try {
			if (verifyingDTO != null) {
				final String keyType = (String) nodeService.getProperty(verifyingDTO.getKeyFile(), SigningModel.PROP_KEYTYPE);
				
				final KeyStore ks = KeyStore.getInstance(keyType);
				final ContentReader keyContentReader = getReader(verifyingDTO.getKeyFile());
				if (keyContentReader != null && ks != null  && verifyingDTO.getKeyPassword() != null) {
					
					// Get crypted secret key and decrypt it
					final Serializable encryptedPropertyValue = nodeService.getProperty(verifyingDTO.getKeyFile(), SigningModel.PROP_KEYCRYPTSECRET);
					final Serializable decryptedPropertyValue = metadataEncryptor.decrypt(SigningModel.PROP_KEYCRYPTSECRET, encryptedPropertyValue);
					
					// Decrypt key content
					final InputStream decryptedKeyContent = CryptUtils.decrypt(decryptedPropertyValue.toString(), keyContentReader.getContentInputStream());
					
					ks.load(new ByteArrayInputStream(IOUtils.toByteArray(decryptedKeyContent)), verifyingDTO.getKeyPassword().toCharArray());
					
					
					final ContentReader fileToVerifyContentReader = getReader(verifyingDTO.getFileToVerify());
					if (fileToVerifyContentReader != null) {
						final PdfReader reader = new PdfReader(fileToVerifyContentReader.getContentInputStream());
						if (reader != null) {
							final AcroFields af = reader.getAcroFields();
							if (af != null) {
								final ArrayList<String> names = af.getSignatureNames();
								if (names != null) {
									for (int k = 0; k < names.size(); ++k) {
										final VerifyResultDTO verifyResultDTO = new VerifyResultDTO();
										final String name = (String)names.get(k);
										verifyResultDTO.setName(name);
										verifyResultDTO.setSignatureCoversWholeDocument(af.signatureCoversWholeDocument(name));
										verifyResultDTO.setRevision(af.getRevision(name));
										verifyResultDTO.setTotalRevision(af.getTotalRevisions());
									   
										final PdfPKCS7 pk = af.verifySignature(name);
										if (pk != null) {
								            @SuppressWarnings("unused")
											final Calendar cal = pk.getSignDate();
								            @SuppressWarnings("unused")
											final Certificate[] pkc = pk.getCertificates();
								            //ITEXT 5.5.11
								            //final List<VerificationException> errors = CertificateVerification.verifyCertificates(pkc, ks, null, cal);
								            //ITEXT 5.1.3
							                X509Certificate certificate = pk.getSigningCertificate();
							                Date date = (pk.getSignDate() != null) ?pk.getSignDate().getTime():null;
							        		String principal = certificate.getSubjectX500Principal().toString();
							        		String serialNumber =  certificate.getSerialNumber().toString();
							        	    Date certificateNotAfter = certificate.getNotAfter();
							        	    String certificateIssuer =  certificate.getIssuerX500Principal().toString();   
							        	    final List<Exception> errors = Arrays.asList(new Exception("Date="+date.getTime()+", Principal="+principal+", SerialNumber="+serialNumber+", CertificateNotAfter="+certificateNotAfter+", Issuer="+certificateIssuer));
								            
								            if (errors.size() == 0) {
								            	verifyResultDTO.setIsSignValid(true);
								            } else {
								            	verifyResultDTO.setIsSignValid(false);
								            }
								            
								            verifyResultDTO.setSignSubject(pk.getSigningCertificate().getSubjectDN().getName());           
											verifyResultDTO.setIsDocumentModified(!pk.verify());
											verifyResultDTO.setSignDate(pk.getSignDate());
											verifyResultDTO.setSignInformationVersion(pk.getSigningInfoVersion());
											verifyResultDTO.setSignVersion(pk.getVersion());
											verifyResultDTO.setSignName(pk.getSignName());
											
											result.add(verifyResultDTO);
										} else {
											log.error("Unable to verify signature.");
											throw new AlfrescoRuntimeException("Unable to verify signature.");
										}
									}
								} else {
									log.error("Unable to get signature names.");
									throw new AlfrescoRuntimeException("Unable to get signature names.");
								}
							} else {
								log.error("Unable to get PDF fields.");
								throw new AlfrescoRuntimeException("Unable to get PDF fields.");
							}
						}
					} else {
						log.error("Unable to get document to verify content.");
						throw new AlfrescoRuntimeException("Unable to get document to verify content.");
					}
				} else {
					log.error("Unable to get key content, key type or key password.");
					throw new AlfrescoRuntimeException("Unable to get key content, key type or key password.");
				}
			} else {
				log.error("No object with verification informations.");
				throw new AlfrescoRuntimeException("No object with verification informations.");
			}
		} catch (KeyStoreException e) {
			log.error(e);
			throw new AlfrescoRuntimeException(e.getMessage(), e);
		} catch (ContentIOException e) {
			log.error(e);
			throw new AlfrescoRuntimeException(e.getMessage(), e);
		} catch (NoSuchAlgorithmException e) {
			log.error(e);
			throw new AlfrescoRuntimeException(e.getMessage(), e);
		} catch (CertificateException e) {
			log.error(e);
			throw new AlfrescoRuntimeException(e.getMessage(), e);
		} catch (IOException e) {
			log.error(e);
			throw new AlfrescoRuntimeException(e.getMessage(), e);
		} catch (GeneralSecurityException e) {
			log.error(e);
			throw new AlfrescoRuntimeException(e.getMessage(), e);
		} catch (Throwable e) {
			log.error(e);
			throw new AlfrescoRuntimeException(e.getMessage(), e);
		}
		
		return result;
	}
	

	
	
    // /**
    //  * Create a rectangle for the visible signature using the selected position and signature size
    //  * 
    //  * @param position
    //  * @param width
    //  * @param height
    //  * @return
    //  */
    // private static Rectangle positionSignature(final String position, final Rectangle pageRect, final int width, final int height, final int marginX, final int marginY) {
    //     final float pageHeight = pageRect.getHeight();
    //     final float pageWidth = pageRect.getWidth();
    //     Rectangle r = null;
    //     if (position.equals(DigitalSigningDTO.POSITION_BOTTOMLEFT)) {
    //         r = new Rectangle(marginX, marginY, width + marginX, height + marginY);
    //     } else if (position.equals(DigitalSigningDTO.POSITION_BOTTOMRIGHT)) {
    //         r = new Rectangle(pageWidth - width - marginX, height + marginY, pageWidth - marginX, marginY);
    //     } else if (position.equals(DigitalSigningDTO.POSITION_TOPLEFT)) {
    //         r = new Rectangle(marginX, pageHeight - marginY , width + marginX, pageHeight - height - marginY);
    //     } else if (position.equals(DigitalSigningDTO.POSITION_TOPRIGHT)) {
    //     	r = new Rectangle(pageWidth - width - marginX, pageHeight - marginY, pageWidth - marginX, pageHeight - height - marginY);
    //     } else if (position.equals(DigitalSigningDTO.POSITION_CENTER)) {
    //         r = new Rectangle((pageWidth / 2) - (width / 2), (pageHeight / 2) - (height / 2),
    //                             (pageWidth / 2) + (width / 2), (pageHeight / 2) + (height / 2));
    //     }
    //     return r;
    // }
    
    /**
     * Determines whether or not a watermark should be applied to a given page
     * 
     * @param pagespage choice
     * @param current current page
     * @param numpages total number of page
     * @return if current page match with page choice 
     */
    // protected static boolean checkPage(final String pages, final int current, final int numpages) {
    //     boolean markPage = false;
    //     /*
    //     if (pages.equals(DigitalSigningDTO.PAGE_EVEN) || pages.equals(DigitalSigningDTO.PAGE_ODD)) {
    //         if (current % 2 == 0) {
    //             markPage = true;
    //         }
    //     } else if (pages.equals(DigitalSigningDTO.PAGE_ODD)) {
    //         if (current % 2 != 0) {
    //             markPage = true;
    //         }
    //     } else 
    //     */
    //     if (pages.equals(DigitalSigningDTO.PAGE_FIRST)) {
    //         if (current == 1) {
    //             markPage = true;
    //         }
    //     } else if (pages.equals(DigitalSigningDTO.PAGE_LAST)) {
    //         if (current == numpages) {
    //             markPage = true;
    //         }
    //     } else if (pages.equals(DigitalSigningDTO.PAGE_LAST)) {
    //         if (current == numpages) {
    //             markPage = true;
    //         }
    //     } else {
    //         markPage = true;
    //     }
        
    //     return markPage;
    // }
	
    /**
     * Gets the X value for centering the watermark image
     * 
     * @param r rectangle
     * @param img image
     * @return
     */
    // protected static float getCenterX(final Rectangle r, final Image img) {
    //     float x = 0;
    //     final float pdfwidth = r.getWidth();
    //     final float imgwidth = img.getWidth();
    //     x = (pdfwidth - imgwidth) / 2;
    //     return x;
    // }


    /**
     * Gets the Y value for centering the watermark image
     * 
     * @param r rectangle
     * @param img image
     * @return
     */
    // protected static float getCenterY(final Rectangle r, final Image img) {
    //     float y = 0;
    //     final float pdfheight = r.getHeight();
    //     final float imgheight = img.getHeight();
    //     y = (pdfheight - imgheight) / 2;
    //     return y;
    // }
    
    
    // protected static BufferedImage scaleImage(final BufferedImage image, final int imageType, int newWidth, int newHeight) {
    //     // Make sure the aspect ratio is maintained, so the image is not distorted
    // 	final double thumbRatio = (double) newWidth / (double) newHeight;
    // 	final int imageWidth = image.getWidth(null);
    // 	final int imageHeight = image.getHeight(null);
    // 	final double aspectRatio = (double) imageWidth / (double) imageHeight;

    //     if (thumbRatio < aspectRatio) {
    //         newHeight = (int) (newWidth / aspectRatio);
    //     } else {
    //         newWidth = (int) (newHeight * aspectRatio);
    //     }

    //     // Draw the scaled image
    //     final BufferedImage newImage = new BufferedImage(newWidth, newHeight, imageType);
    //     final Graphics2D graphics2D = newImage.createGraphics();
    //     graphics2D.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);
    //     graphics2D.drawImage(image, 0, 0, newWidth, newHeight, null);
    //     graphics2D.dispose();

    //     return newImage;
    // }
    
    /**
     * @param actionedUponNodeRef
     * @return
     */
    protected ContentReader getReader(NodeRef nodeRef) {
        // First check that the node is a sub-type of content
        QName typeQName = nodeService.getType(nodeRef);
        if (dictionaryService.isSubClass(typeQName, ContentModel.TYPE_CONTENT) == false) {
            // it is not content, so can't transform
            return null;
        }

        // Get the content reader
        ContentReader contentReader = contentService.getReader(nodeRef, ContentModel.PROP_CONTENT);

        return contentReader;
    }
    
    /**
     * @param ruleAction
     * @param filename
     * @return
     */
    protected NodeRef createDestinationNode(String filename, NodeRef destinationParent, NodeRef target) {
        NodeRef destinationNode;
        FileInfo fileInfo = fileFolderService.create(destinationParent, filename, ContentModel.TYPE_CONTENT);
        destinationNode = fileInfo.getNodeRef();

        return destinationNode;
    }

    private File convertPdfToPdfA(final InputStream source) throws IOException, DocumentException {
        File tempFile = null;       
        File pdfAFile = null;
        OutputStream output = null;
        try {
            tempFile = TempFileProvider.createTempFile("pre_pdfa", ".pdf");           
            FileUtils.copyInputStreamToFile(source, tempFile);          
            pdfAFile = TempFileProvider.createTempFile("digitalSigning-" + System.currentTimeMillis(), ".pdf");
            //METHOD WITH ITEXT 5
            /*
            java.net.URL url = getClass().getResource("/org/alfresco/plugin/digitalSigning/service/sRGB_CS_profile.icm");
        	byte[] bytes = IOUtils.toByteArray(url.openStream());
        	final ICC_Profile icc = ICC_Profile.getInstance(bytes);
        	
            //Reads a PDF document. 
            PdfReader reader = new PdfReader(source); 
            //PdfStamper: Applies extra content to the pages of a PDF document. This extra content can be all the objects allowed in 
            //PdfContentByte including pages from other Pdfs. 
            //A generic Document class. 
            Document document = new Document(); 
            // we create a writer that listens to the document
            PdfAWriter writer = PdfAWriter.getInstance(document, new FileOutputStream(pdfAFile), PdfAConformanceLevel.PDF_A_1A);       
            int numberPages = reader.getNumberOfPages(); 

            //PdfDictionary:A dictionary is an associative table containing pairs of objects. 
            //The first element of each pair is called the key and the second  element is called the value 
            //<CODE>PdfName</CODE> is an object that can be used as a name in a PDF-file 
            //PdfDictionary outi = new PdfDictionary(PdfName.OUTPUTINTENT); 
            //outi.put(PdfName.OUTPUTCONDITIONIDENTIFIER, new PdfString("sRGB IEC61966-2.1")); 
            //outi.put(PdfName.INFO, new PdfString("sRGB IEC61966-2.1")); 
            //outi.put(PdfName.S, PdfName.GTS_PDFA1); 
            //writer.getExtraCatalog().put(PdfName.OUTPUTINTENTS, new PdfArray(outi)); 

            writer.setTagged();
            writer.createXmpMetadata();
            document.open(); 
            
            writer.setOutputIntents("Custom", "", "http://www.color.org", "sRGB IEC61966-2.1", icc);

            //Add pages 
            PdfImportedPage p = null; 
            Image image; 
            for(int i=0; i< numberPages; i++){ 
            	document.newPage(); 
                p = writer.getImportedPage(reader, i+1); 
                image = Image.getInstance(p);
                // Scale PDF page to fit with PDF/A format
                image.scaleAbsolute(writer.getPageSize());
                // Center the image into the PDF/A page
                image.setAlignment(Element.ALIGN_CENTER);
                
                // Set the position of the image into the PDF/A page
                image.setAbsolutePosition(0, 0);
                document.setMargins(0, 0, 0, 0);
                document.add(image); 
            }
            
            document.close(); 
            writer.flush();

            return pdfAFile;
            */
            //METHOD WITH PDFBOX 1.8.10
            //https://apache.googlesource.com/pdfbox/+/4df9353eaac3c4ee2124b09da05312376f021b2c/examples/src/main/java/org/apache/pdfbox/examples/pdfa/CreatePDFA.java
    		PDDocument doc = null;
    		try{
    			doc = PDDocument.load(tempFile);
    		}catch(IOException ex){
    			if(ex.getMessage().contains("expected='endstream'")){
    				//https://issues.apache.org/jira/browse/PDFBOX-1541
    				//https://www.programcreek.com/java-api-examples/?code=jmrozanec/pdf-converter/pdf-converter-master/src/main/java/pdf/converter/txt/TxtCreator.java				
    				File tmpfile = File.createTempFile(String.format("txttmp-%s", UUID.randomUUID().toString()), null);
    	            try{
    					org.apache.pdfbox.io.RandomAccessFile raf = new org.apache.pdfbox.io.RandomAccessFile(tmpfile, "rw");
    		            doc = PDDocument.loadNonSeq(tmpfile,raf);	   	
    	            }finally{
    	            	FileUtils.deleteQuietly(tmpfile);
    	            }
    			}else{
    				throw ex;
    			}
    		}   
            try
            {           
//                // load the font from pdfbox.jar
//                InputStream fontStream = CreatePDFA.class.getResourceAsStream("/org/apache/pdfbox/resources/ttf/ArialMT.ttf");
//                PDFont font = PDTrueTypeFont.loadTTF(doc, fontStream);
//                
//                
//                // create a page with the message where needed
//                PDPageContentStream contentStream = new PDPageContentStream(doc, page);
//                contentStream.beginText();
//                contentStream.setFont( font, 12 );
//                contentStream.moveTextPositionByAmount( 100, 700 );
//                contentStream.drawString( message );
//                contentStream.endText();
//                contentStream.saveGraphicsState();
//                contentStream.close();

                PDDocumentCatalog cat = doc.getDocumentCatalog();
                PDMetadata metadata = new PDMetadata(doc);
                cat.setMetadata(metadata);

                XMPMetadata xmp = XMPMetadata.createXMPMetadata();
                try
                {
                    PDFAIdentificationSchema pdfaid = xmp.createAndAddPFAIdentificationSchema();
                    pdfaid.setConformance("B");
                    pdfaid.setPart(1);
                    pdfaid.setAboutAsSimple("PDFBox PDFA sample");
                    XmpSerializer serializer = new XmpSerializer();
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    serializer.serialize(xmp, baos, true);
                    metadata.importXMPMetadata( baos.toByteArray() );
                }
                catch(BadFieldValueException badFieldexception)
                {
                    // can't happen here, as the provided value is valid
                }
                //catch(XmpSerializationException xmpException)
                //{
                //    System.err.println(xmpException.getMessage());
                //}
                //COLOR SPACE BUG
                InputStream colorProfile = CreatePDFA.class.getResourceAsStream("/org/apache/pdfbox/resources/pdfa/sRGB Color Space Profile.icm");
                //InputStream colorProfile = getClass().getResourceAsStream("/org/alfresco/plugin/digitalSigning/service/sRGB_CS_profile.icm");
                // create output intent
                PDOutputIntent oi = new PDOutputIntent(doc, colorProfile); 
                oi.setInfo("sRGB IEC61966-2.1"); 
                oi.setOutputCondition("sRGB IEC61966-2.1");
                oi.setOutputConditionIdentifier("sRGB IEC61966-2.1"); 
                oi.setRegistryName("http://www.color.org"); 
                cat.addOutputIntent(oi);
                
                doc.save(pdfAFile);
               
            }
            finally
            {
                if( doc != null )
                {
                    doc.close();
                }
            }
            return pdfAFile;
        }
        catch (Exception ex) {
        	log.error("Can't convert PDF to PDF/A.  Error during conversion to PDF/A.", ex);
        	throw new IOException("Can't convert PDF to PDF/A.  Error during conversion to PDF/A.", ex);
        }   
        finally {
            if (tempFile != null) {
                tempFile.delete();
            }
            if(output!=null){
            	output.close();
            }
        }
    	
    }

	/**
	 * @param nodeService the nodeService to set
	 */
	public final void setNodeService(NodeService nodeService) {
		this.nodeService = nodeService;
	}


	/**
	 * @param dictionaryService the dictionaryService to set
	 */
	public final void setDictionaryService(DictionaryService dictionaryService) {
		this.dictionaryService = dictionaryService;
	}


	/**
	 * @param contentService the contentService to set
	 */
	public final void setContentService(ContentService contentService) {
		this.contentService = contentService;
	}


	/**
	 * @param fileFolderService the fileFolderService to set
	 */
	public final void setFileFolderService(FileFolderService fileFolderService) {
		this.fileFolderService = fileFolderService;
	}


	/**
	 * @param contentTransformerRegistry the contentTransformerRegistry to set
	 */
	public final void setContentTransformerRegistry(
			ContentTransformerRegistry contentTransformerRegistry) {
		this.contentTransformerRegistry = contentTransformerRegistry;
	}


	/**
	 * @param metadataEncryptor the metadataEncryptor to set
	 */
	public final void setMetadataEncryptor(MetadataEncryptor metadataEncryptor) {
		this.metadataEncryptor = metadataEncryptor;
	}
	

	}
