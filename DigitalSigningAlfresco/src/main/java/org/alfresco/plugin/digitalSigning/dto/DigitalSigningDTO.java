/**
 * 
 */
package org.alfresco.plugin.digitalSigning.dto;

import java.util.List;

import org.alfresco.service.cmr.repository.NodeRef;

/**
 * Signing DTO.
 * 
 * @author Emmanuel ROUX
 *
 */
public class DigitalSigningDTO {
	
	/**
	 * Signing page.
	 */
	public static final String PAGE_FIRST = "first";
	public static final String PAGE_LAST = "last";
	/*
	public static final String PAGE_ALL = "all";
	public static final String PAGE_ODD = "odd";
    public static final String PAGE_EVEN = "even";
    */
    public static final String PAGE_SPECIFIC = "specific";

    /**
     * Sign position.
     */
    public static final String POSITION_CENTER = "center";
    public static final String POSITION_TOPLEFT = "topleft";
    public static final String POSITION_TOPRIGHT = "topright";
    public static final String POSITION_BOTTOMLEFT = "bottomleft";
    public static final String POSITION_BOTTOMRIGHT = "bottomright";
    public static final String POSITION_CUSTOM = "custom";
    
    /**
     * Image depth.
     */
    public static final String DEPTH_UNDER = "under";
    public static final String DEPTH_OVER = "over";
	
	
	/**
	 * File to sign.
	 */
	private List<NodeRef> filesToSign;
	
	/**
	 * Key file to sign.
	 */
	private NodeRef keyFile;
	
	/**
	 * Key password.
	 */
	private String keyPassword;
	
	/**
	 * Generated file destination folder.
	 */
	private NodeRef destinationFolder;
	
	
	/**
	 * @return the fileToSign
	 */
	public final List<NodeRef> getFilesToSign() {
		return filesToSign;
	}

	/**
	 * @param fileToSign the fileToSign to set
	 */
	public final void setFilesToSign(List<NodeRef> filesToSign) {
		this.filesToSign = filesToSign;
	}

	/**
	 * @return the keyFile
	 */
	public final NodeRef getKeyFile() {
		return keyFile;
	}

	/**
	 * @param keyFile the keyFile to set
	 */
	public final void setKeyFile(NodeRef keyFile) {
		this.keyFile = keyFile;
	}

	/**
	 * @return the keyPassword
	 */
	public final String getKeyPassword() {
		return keyPassword;
	}

	/**
	 * @param keyPassword the keyPassword to set
	 */
	public final void setKeyPassword(String keyPassword) {
		this.keyPassword = keyPassword;
	}


	


	

	/**
	 * @return the destinationFolder
	 */
	public final NodeRef getDestinationFolder() {
		return destinationFolder;
	}

	/**
	 * @param destinationFolder the destinationFolder to set
	 */
	public final void setDestinationFolder(NodeRef destinationFolder) {
		this.destinationFolder = destinationFolder;
	}
	
}
