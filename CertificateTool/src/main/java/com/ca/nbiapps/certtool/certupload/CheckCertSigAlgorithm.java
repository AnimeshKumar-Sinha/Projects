package com.ca.nbiapps.certtool.certupload;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Properties;

//import com.arcot.apps.callouts.sslconfig.*;
import com.arcot.crypto.Base64;
import com.arcot.crypto.CryptoUtil;
import com.arcot.database.DatabaseConnection;
import com.arcot.logger.ArcotLogger;
import com.ca.nbiapps.certtool.dboperations.DBWrapper;

import sun.security.pkcs.PKCS7;

public class CheckCertSigAlgorithm
{

    // PEM Cerificate format
    private String PEM_CERTIFICATE_START = "-----BEGIN CERTIFICATE-----";

	private boolean softEncrypt = false;
	private boolean jniInitized = false;
    private Properties prop = null;
    private Connection connection = null;
	private DatabaseConnection conn = null;
    private String connectionType = null;
    private String masterKey = null;
    private int currentKeyStoreUploadCount = 0;
    private int currentTrustStoreUploadCount = 0;

    public CheckCertSigAlgorithm()
    {
        try
        {
            prop = new Properties();
			InputStream in = this.getClass().getResourceAsStream("/certsUpload.properties");
			if (in != null)
			    ArcotLogger.logInfo("In CheckCertSigAlgorithm: properties loaded");
			else
			    ArcotLogger.logError("In CheckCertSigAlgorithm: properties not loaded");
			prop.load(in);
			in.close();
        }
        catch(IOException ex)
        {
            ex.printStackTrace();
        }
    }

    public static void printUsage()
    {
        System.out.println("\n\nTool Usage:");
        System.out.println("\n\n1. Check signature Algorithm for certificates in ARSignCert table");
        System.out.println("\nCheckCertSigAlgorithm -s [-o Result_File]");
        System.out.println("\n\n2. Check signature Algorithm for certificates in ARCalloutSSLConfig table");
        System.out.println("\nCheckCertSigAlgorithm -c [-o Result_File]");
        System.out.println("\nExample:");
        System.out.println("\njava CheckCertSigAlgorithm -s");
        System.out.println("\njava CheckCertSigAlgorithm -c");
        System.out.println("\njava CheckCertSigAlgorithm -s -o SigningCertAlg.txt");
        System.out.println("\njava CheckCertSigAlgorithm -c -o CalloutCertAlg.txt");

        System.exit(0);
    } // end of method - printUsage

    private boolean initConnection()
    {
		boolean initResult = true;

        try
        {
            Class.forName("oracle.jdbc.driver.OracleDriver");
        }
        catch(ClassNotFoundException e)
        {
            ArcotLogger.logError("In CheckCertSigAlgorithm.initConnection: Cannot find JDBC Driver JAR file.", e);
        }
        String jdbcUrl = null;
        String dbuser = null;
        String dbpasswd = null;
        String keyStoreFile = null;
        String keyStoreType = null;
        String keyStorePassword = null;
        String trustStoreFile = null;
        String trustStoreType = null;
        String trustStorePassword = null;
        String printSql = null;
        String softEncryptStr = null;

		jdbcUrl = prop.getProperty("jdbcurl");
		dbuser = prop.getProperty("dbuser");
		dbpasswd = prop.getProperty("dbpassword");
        keyStoreFile = prop.getProperty("keyStoreFile");
        keyStoreType = prop.getProperty("keyStoreType");
        keyStorePassword = prop.getProperty("keyStorePassword");
        trustStoreFile = prop.getProperty("trustStoreFile");
        trustStoreType = prop.getProperty("trustStoreType");
        trustStorePassword = prop.getProperty("trustStorePassword");
        connectionType = prop.getProperty("dbConnType");

        softEncryptStr = prop.getProperty("SoftEncrypt");
		if (softEncryptStr != null && !"".equals(softEncryptStr))
		{
			if (softEncryptStr.equals("1"))
        	    softEncrypt = true;
		    else
        	    softEncrypt = false;
		}

        ArcotLogger.logInfo("In CheckCertSigAlgorithm.initConnection: softEncrypt = " + softEncrypt);
        ArcotLogger.logInfo("In CheckCertSigAlgorithm.initConnection: connectionType = " + connectionType);
        ArcotLogger.logInfo("In CheckCertSigAlgorithm.initConnection: jdbcUrl = " + jdbcUrl);

		masterKey = prop.getProperty("encryptionKey");
		if (masterKey != null && !"".equals(masterKey))
            masterKey = new String(Base64.decode(masterKey));
	    else
	    {
		    ArcotLogger.logError("In CheckCertSigAlgorithm.initConnection: Cannot get MasterKey value from properties file.");
        	initResult = false;

        	return initResult;
		}

        Properties props = new Properties();
        if(jdbcUrl != null && jdbcUrl.indexOf("PROTOCOL=tcps") != -1)
        {
            props.setProperty("user", dbuser);
            props.setProperty("password", dbpasswd);

            if(trustStoreFile != null && !"".equals(trustStoreFile))
            {
                props.setProperty("javax.net.ssl.trustStore", trustStoreFile);
                props.setProperty("javax.net.ssl.trustStoreType", trustStoreType);
                props.setProperty("javax.net.ssl.trustStorePassword", trustStorePassword);
            }
            if(keyStoreFile != null && !"".equals(keyStoreFile))
            {
                props.setProperty("javax.net.ssl.keyStore", keyStoreFile);
                props.setProperty("javax.net.ssl.keyStoreType", keyStoreType);
                props.setProperty("javax.net.ssl.keyStorePassword", keyStorePassword);
            }
        }

        try
        {
			boolean gotConnection = false;
            if(connectionType != null && connectionType.equalsIgnoreCase("admin"))
            {
				ArcotLogger.logInfo("In CheckCertSigAlgorithm.initConnection: Use TransFort DBHandler class to manage DB connections!");
                conn = new DBWrapper().getAdminConnection();
                if (conn == null)
                {
                    connectionType = "transfort";
				    ArcotLogger.logInfo("In CheckCertSigAlgorithm.initConnection: Failed with Admin connection. Use TransFort Type to connect.");
			    }
			    else
			        gotConnection = true;
		    }

 		    if (!gotConnection && connectionType != null && connectionType.equalsIgnoreCase("transfort"))
            {
				ArcotLogger.logInfo("In CheckCertSigAlgorithm.initConnection: Use TransFort vpaspwd.ini settings to manage DB connections!");
                if (jdbcUrl.indexOf("PROTOCOL=tcps") != -1)
                    connection = new DBWrapper(jdbcUrl,dbuser).getConnection(props);
                else
                    connection = new DBWrapper(jdbcUrl,dbuser, softEncrypt).getConnection();

                if (connection != null)
			        gotConnection = true;
		    }

            if (!gotConnection)
            {
				ArcotLogger.logInfo("In CheckCertSigAlgorithm.initConnection: Use JDBC driver connection to manage DB connections!");
                connection = new DBWrapper(jdbcUrl,dbuser,dbpasswd).getConnection();
                initResult = false;
            }
        }
        catch(Exception e)
        {
            ArcotLogger.logError("In CheckCertSigAlgorithm.initConnection: Connection Failed!", e);
            initResult = false;
        }

        return initResult;
	}

	public String getTimeStr(java.util.Date date)
	{
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy_MM_dd_HH_mm_ss");
        if (date == null)
            date = new java.util.Date();

        return "_" + dateFormat.format(date);
	}

	public String getLogTimeHeader(java.util.Date date)
	{
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS - ");
        if (date == null)
            date = new java.util.Date();

        if (!jniInitized)
        {
			jniInitized = true;
			return "\n\n" + dateFormat.format(date);
		}
		else
            return dateFormat.format(date);
	}

	public String getConfNameByConfID(int confId)
	{
		ByteArrayInputStream bais = null;
        PreparedStatement pStmt = null;
        ResultSet rs = null;
		String selectDisplayIDStmt = "select DisplayID from ARCalloutsConfig where ConfID = " + Integer.toString(confId);
		String displayID = null;

		// check if this is for Silo Default
		if (confId == 0)
		    return "SILO_DEFAULT";

		try
		{
			initConnection();

			if (connectionType != null && connectionType.equalsIgnoreCase("admin"))
				pStmt = conn.prepareStatement(selectDisplayIDStmt);
			else
				pStmt = connection.prepareStatement(selectDisplayIDStmt);

			rs = pStmt.executeQuery();

			if (rs.next())
				displayID = rs.getString(1);
			else
				ArcotLogger.logError("In CheckCertSigAlgorithm.getConfNameByConfID: Failed to execute query: " + selectDisplayIDStmt);
		}
		catch(Exception e)
		{
			ArcotLogger.logError("In CheckCertSigAlgorithm.getConfNameByConfID: SQL Failed!", e);
		}
		finally
		{
			try
			{
				if (pStmt != null)
					pStmt.close();
				if (rs != null)
					rs.close();
			}
			catch(Exception e)
			{
				ArcotLogger.logError("In CheckCertSigAlgorithm.getConfNameByConfID: Error in Final Block", e);
			}
			try
			{
				if(connection != null)
					connection.close();
				if(conn != null)
					new DBWrapper().releaseAdminConnection(conn);
				ArcotLogger.logInfo("In CheckCertSigAlgorithm.getConfNameByConfID: DB connection Released.");
			}
			catch(Exception e)
			{
				ArcotLogger.logError("In CheckCertSigAlgorithm.getConfNameByConfID: Error in closing DB connection", e);
			}
		}
		return displayID;
	}

	public static X509Certificate[] orderCertificateChain(X509Certificate[] certs)
	{
		if (certs.length == 1)
		    return certs;

		X509Certificate[] orderedCerts = new X509Certificate[certs.length];

		int idx = 0;
		int orderedCount = 0;
		X509Certificate cert = null;
		X509Certificate parentCert = null;

		for (idx = 0;idx < certs.length;idx++)
		{
			cert = (X509Certificate) certs[idx];

			// check for the root cert and add the root cert to the end of the new orderedCerts
			if (orderedCount == 0)
			{
				if (cert.getSubjectDN().getName().equals(cert.getIssuerDN().getName()))
				{
				    orderedCerts[certs.length-orderedCount-1] = cert;
				    parentCert = cert;
				    idx = -1;
			        orderedCount++;
			    }
			    else
			        continue;
			}
		    else if (parentCert.getSubjectDN().getName().equals(cert.getIssuerDN().getName()))
			{
				orderedCerts[certs.length-orderedCount-1] = cert;
				parentCert = cert;
				idx = -1;
			    orderedCount++;
			}

			if (orderedCount == certs.length)
			    break;
		}

		// if cannot find a match of the root cert, then return the original certificates)
		if (orderedCount == 0)
		    return certs;

		return orderedCerts;
	}

    // load certificate from file input stream
    public X509Certificate[] loadCertificates(byte[] certBytes)
    {
        System.out.println("Trying to load the certificate as X509 Certificate");
        BufferedInputStream bis = null;
        CertificateFactory certFact = null;
        X509Certificate[] certs = null;

        try
        {
            System.out.println("Reading from File...");
            bis = new BufferedInputStream(new ByteArrayInputStream(certBytes));
        }
        catch(Exception e)
        {
            System.out.println("Could not locate certfile");
            e.printStackTrace();
        }

        try
        {
            System.out.println("Parsing certificates...");
            certFact = CertificateFactory.getInstance("X.509");
            Collection c = certFact.generateCertificates(bis);

            System.out.println("Number of certificate files: " + c.size());
            certs = new X509Certificate[c.size()];
            int counter = 0;

			Iterator i = c.iterator();
			while (i.hasNext())
			{
			    certs[counter] = (X509Certificate)i.next();
			    counter++;
			 }

            bis.close();
        }
        catch(Exception e)
        {
            System.out.println("Could not instantiate cert");
            e.printStackTrace();
        }
        return certs;

    }

	public String getSigAlgorithm(byte[] certBytes)
	{
        StringBuffer certBuffer = new StringBuffer();
        StringBuffer subjectDNBuffer = new StringBuffer();
        StringBuffer issuerDNBuffer = new StringBuffer();
        InputStream ios = new ByteArrayInputStream(certBytes);
        boolean isP7BCert = false;
        X509Certificate[] certs = null;
        PKCS7 pkcs7 = null;
        String sigAlgorithm = null;

        if (certBytes == null)
            return "";

        try
        {
            pkcs7 = new PKCS7(ios);
            isP7BCert = true;
            if (ios != null)
                ios.close();
        }
        catch(Exception e)
        {
            ArcotLogger.logInfo("In CheckCertSigAlgorithm.getCertificateInfo: certificate/key is not PKCS#7 format");
        }

        if (isP7BCert)
            certs = orderCertificateChain(pkcs7.getCertificates());
        else
            certs = orderCertificateChain(loadCertificates(certBytes));

        ArcotLogger.logInfo("In CheckCertSigAlgorithm.getCertificateInfo: The target blob contains " + certs.length + " X509 certificate(s)");
        X509Certificate publicKey = certs[0];
        sigAlgorithm = publicKey.getSigAlgName();

        return sigAlgorithm;
    }

	public void writeOutputFile(Writer csvWriter, String csvLine)
	{
		try
		{
		    csvWriter.write(csvLine + "\n");
		    csvWriter.flush();
		}
		catch(Exception e)
		{
			System.out.println(getLogTimeHeader(null) + "In CheckCertSigAlgorithm.writeOutputFile: Error occurred during output of upload error. Reason: " + e.getMessage());
		}
	}

	public boolean checkSigningCerts(String outputFileName)
	{
		boolean retValue = true;
		boolean writeToConsole = false;
        Writer csvWriter = null;
        PreparedStatement stmt = null;
		int colIdx = 1;
		ResultSet rs = null;

		String selectStmt = "select  distinct certid, certChainName, certChain from ARSigningCert order by certid asc";

		try
		{
			initConnection();

            if (outputFileName != null)
            {
			    csvWriter = new FileWriter(outputFileName);
                ArcotLogger.logInfo("In CheckCertSigAlgorithm.checkSigningCerts: Output ARSigningCert table certificate signature algorithm information.");
			    writeOutputFile(csvWriter, "certId, displayID, SigAlgorithm");
			}
			else
			{
                System.out.println(getLogTimeHeader(null) + "In CheckCertSigAlgorithm.checkSigningCerts: Output ARSigningCert table certificate signature algorithm information.");
			    System.out.println("certId, displayID, SigAlgorithm");
			    writeToConsole = true;
			}

			if (connectionType != null && connectionType.equalsIgnoreCase("admin"))
				stmt = conn.prepareStatement(selectStmt);
			else
				stmt = connection.prepareStatement(selectStmt);

			stmt.setQueryTimeout(10);
			rs = stmt.executeQuery();

			int certId = -1;
			String displayID = null;
			String sigAlgorithm = null;
			byte[] certBytes = null;

			while (rs.next())
			{
				certId = rs.getInt(1);
				displayID = rs.getString(2);
				certBytes = rs.getBytes(3);

				if (certBytes != null && certBytes.length != 0)
				{
					ArcotLogger.logInfo("In CheckCertSigAlgorithm.checkSigningCerts: received cert bytes length is " + certBytes.length);
					try
					{
					    sigAlgorithm = getSigAlgorithm(certBytes);
					}
					catch(Exception es)
					{
						ArcotLogger.logError("In CheckCertSigAlgorithm.checkSigningCerts: Issue in writing signature algorithm",es);
						ArcotLogger.logError("In CheckCertSigAlgorithm.checkSigningCerts: Error Certificate - [certId, displayID] = [" + certId + "," + displayID + "]");
						if (!writeToConsole)
							writeOutputFile(csvWriter, certId + ", " + displayID + ", " + "Invalid Certificate");
						else
							System.out.println(certId + ", " + displayID + ", Invalid Certificate");

						continue;
					}
					if (!writeToConsole)
					    writeOutputFile(csvWriter, certId + ", " + displayID + ", " + sigAlgorithm);
					else
					    System.out.println(certId + ", " + displayID + ", " + sigAlgorithm);
				}
				else
				{
					ArcotLogger.logError("In CheckCertSigAlgorithm.checkSigningCerts: received cert bytes length is " + certBytes.length);
					writeOutputFile(csvWriter, certId + ", " + displayID + ", No Certificate");
				}
			}
		}
		catch (SQLException sqle)
		{
			ArcotLogger.logError("In CheckCertSigAlgorithm.checkSigningCerts: Issue in writing signature algorithm",sqle);
			retValue = false;
		}
		catch (Exception e)
		{
			ArcotLogger.logError("In CheckCertSigAlgorithm.checkSigningCerts: Issue in writing signature algorithm",e);
			retValue = false;
		}
		finally
		{
			try
			{
				if (rs != null)
					rs.close();

				if ( stmt != null )
					stmt.close();
			}
			catch ( SQLException sqle )
			{
				ArcotLogger.logError("In CheckCertSigAlgorithm.checkSigningCerts: Issue in Creating the CertificateConfig Cache",sqle);
				retValue = false;
			}

			try
			{
				if(connection != null)
					connection.close();
				if(conn != null)
					new DBWrapper().releaseAdminConnection(conn);
				ArcotLogger.logInfo("In CheckCertSigAlgorithm.checkSigningCerts: DB connection Released.");
			}
			catch(Exception e)
			{
				ArcotLogger.logError("In CheckCertSigAlgorithm.checkSigningCerts: Error in closing DB connection", e);
				retValue = false;
			}
		}
		return retValue;
	}

	public String checkStoreType(byte[] storeBytes, String passPhrase)
	{
		String bundleType = "JKS";

		if (passPhrase == null || storeBytes == null)
			return null;

		InputStream ios = new ByteArrayInputStream(storeBytes);
		KeyStore keyStore = null;

        try
        {
			bundleType = "JKS";
			keyStore = KeyStore.getInstance("JKS");
            keyStore.load(ios, passPhrase.toCharArray());
		}
		catch(IOException e)
		{
			if (e.getCause() instanceof UnrecoverableKeyException)
			    ArcotLogger.logError("In CheckCertSigAlgorithm.checkStoreType: store passphrase might not be correct. Failure reason: " + e.getMessage());
			else
			{
				try
				{
					// Try loading with different bundle type to verify if the store is of that type
					keyStore = KeyStore.getInstance("PKCS12");
		            keyStore.load(ios, passPhrase.toCharArray());
		            bundleType = "PKCS12";
				}
				catch(IOException ex)
				{
					if (ex.getCause() instanceof UnrecoverableKeyException)
						ArcotLogger.logError("In CheckCertSigAlgorithm.checkStoreType: store passphrase might not be correct. Failure reason: " + ex.getMessage());
					else
					    ArcotLogger.logError("In CheckCertSigAlgorithm.checkStoreType: IOException Occurred. Failure reason: " + ex.getMessage());
				}
				catch(KeyStoreException ex)
				{
					ArcotLogger.logError("In CheckCertSigAlgorithm.checkStoreType: intended file is not valid " + bundleType + "Failure reason: " + ex.getMessage());
				}
				catch(NoSuchAlgorithmException ex)
				{
					ArcotLogger.logError("In CheckCertSigAlgorithm.checkStoreType: intended file is not valid " + bundleType + "Failure reason: " + ex.getMessage());
				}
				catch(CertificateException ex)
				{
					ArcotLogger.logError("In CheckCertSigAlgorithm.checkStoreType: intended file is not valid " + bundleType + "Failure reason: " + ex.getMessage());
				}
				finally
				{
					try
					{
						if (ios != null)
							ios.close();
					}
					catch(Exception ex1)
					{
					}
				}
			}
		}
		catch(KeyStoreException e)
		{
		    ArcotLogger.logError("In CheckCertSigAlgorithm.checkStoreType: intended file is not valid " + bundleType + "Failure reason: " + e.getMessage());
		}
		catch(NoSuchAlgorithmException e)
		{
		    ArcotLogger.logError("In CheckCertSigAlgorithm.checkStoreType: intended file is not valid " + bundleType + "Failure reason: " + e.getMessage());
		}
		catch(CertificateException e)
		{
		    ArcotLogger.logError("In CheckCertSigAlgorithm.checkStoreType: intended file is not valid " + bundleType + "Failure reason: " + e.getMessage());
		}
		finally
		{
			try
			{
				if (ios != null)
					ios.close();
			}
			catch(Exception ex2)
			{
			}
		}

		return bundleType;
	}

	public String getJKSSigAlgorithm(byte[] storeBytes, String passPhrase)
	{
        String sigAlgorithm = "";
		String storeType = null;
		InputStream ios = null;
		KeyStore keyStore = null;

        try
        {
			storeType = checkStoreType(storeBytes, passPhrase);
			if("PKCS12".equals(storeType))
				keyStore = KeyStore.getInstance("PKCS12");
			else
				keyStore = KeyStore.getInstance("JKS");

			ios = new ByteArrayInputStream(storeBytes);
            keyStore.load(ios, passPhrase.toCharArray());

			Enumeration<String> keyEnum = keyStore.aliases();
			String elem = null;
			boolean isFirstElem = true;
			while(keyEnum.hasMoreElements())
			{
				elem = (String)keyEnum.nextElement();
				if (keyStore.getCertificate(elem).getType().equals("X.509"))
				{
					if (isFirstElem)
					{
					    sigAlgorithm += ((X509Certificate) keyStore.getCertificate(elem)).getSigAlgName();
					    isFirstElem = false;
					}
					else
					    sigAlgorithm +=  "," + ((X509Certificate) keyStore.getCertificate(elem)).getSigAlgName();
			    }
			}
		}
		catch(IOException e)
		{
			if (e.getCause() instanceof UnrecoverableKeyException)
			    ArcotLogger.logError("In CheckCertSigAlgorithm.getJKSSigAlgorithm: store passphrase might not be correct. Failure reason: " + e.getMessage());
			else
			    ArcotLogger.logError("In CheckCertSigAlgorithm.getJKSSigAlgorithm: IOException Occurred. Failure reason: " + e.getMessage());
		}
		catch(KeyStoreException e)
		{
		    ArcotLogger.logError("In CheckCertSigAlgorithm.getJKSSigAlgorithm: intended file is not valid " + "Failure reason: " + e.getMessage());
		}
		catch(NoSuchAlgorithmException e)
		{
		    ArcotLogger.logError("In CheckCertSigAlgorithm.getJKSSigAlgorithm: intended file is not valid " + "Failure reason: " + e.getMessage());
		}
		catch(CertificateException e)
		{
		    ArcotLogger.logError("In CheckCertSigAlgorithm.getJKSSigAlgorithm: intended file is not valid " + "Failure reason: " + e.getMessage());
		}
		return sigAlgorithm;
	}

	public boolean checkCalloutCerts(String outputFileName)
	{
		boolean retValue = true;
		boolean writeToConsole = false;
        Writer csvWriter = null;
        PreparedStatement stmt = null;
		int colIdx = 1;
		ResultSet rs = null;

		String selectStmt = "select  distinct confid, keystore, keypassphrase, truststore, trustpassphrase from ARCalloutSSLConfig order by confid asc";

		try
		{
			initConnection();

            if (outputFileName != null)
            {
			    csvWriter = new FileWriter(outputFileName);
                ArcotLogger.logInfo("In CheckCertSigAlgorithm.checkCalloutCerts: Output ARCalloutSSLConfig table certificate signature algorithm information.");
			    writeOutputFile(csvWriter, "certId, displayID, sigAlgorithm");
			}
			else
			{
                System.out.println(getLogTimeHeader(null) + "In CheckCertSigAlgorithm.checkCalloutCerts: Output ARCalloutSSLConfig table certificate signature algorithm information.");
			    System.out.println("confid, Callout Configuration, Keystore SigAlgorithm, Truststore SigAlgorithm");
			    writeToConsole = true;
			}

			if (connectionType != null && connectionType.equalsIgnoreCase("admin"))
				stmt = conn.prepareStatement(selectStmt);
			else
				stmt = connection.prepareStatement(selectStmt);

			stmt.setQueryTimeout(10);
			rs = stmt.executeQuery();

			int confId = -1;
			String displayID = null;
			String sigAlgorithm = null;
			String[] sigAlgs = null;
			String keyPassPhrase = null;
			String trustPassPhrase = null;
			byte[] keyStoreBytes = null;
			byte[] trustStoreBytes = null;

			while (rs.next())
			{
				confId = rs.getInt(1);
				displayID = getConfNameByConfID(confId);
				keyStoreBytes = rs.getBytes(2);
				trustStoreBytes = rs.getBytes(4);

				if (rs.getString(3) != null || !"".equals(rs.getString(3)))
				    keyPassPhrase = CryptoUtil.decrypt3DES64Ex(masterKey, rs.getString(3), softEncrypt, 0);

				if (rs.getString(5) != null || !"".equals(rs.getString(5)))
				    trustPassPhrase = CryptoUtil.decrypt3DES64Ex(masterKey, rs.getString(5), softEncrypt, 0);

				if (keyStoreBytes != null && keyStoreBytes.length != 0)
				{
					ArcotLogger.logInfo("In CheckCertSigAlgorithm.checkCalloutCerts: received keystore bytes length is " + keyStoreBytes.length);
					sigAlgs = getJKSSigAlgorithm(keyStoreBytes, keyPassPhrase).split(",", -1);

					for (int idx = 0;idx < sigAlgs.length;idx++)
					{
						sigAlgorithm = sigAlgs[idx];
						if (!writeToConsole)
							writeOutputFile(csvWriter, Integer.toString(confId) + ", " + displayID + ", KeyStore: " + sigAlgorithm);
						else
							System.out.println(confId + ", " + displayID + ", KeyStore: " + sigAlgorithm);
					}
				}
				if (trustStoreBytes != null && trustStoreBytes.length != 0)
				{
					ArcotLogger.logInfo("In CheckCertSigAlgorithm.checkCalloutCerts: received truststore bytes length is " + trustStoreBytes.length);
					sigAlgs = getJKSSigAlgorithm(trustStoreBytes, trustPassPhrase).split(",", -1);

					for (int idx = 0;idx < sigAlgs.length;idx++)
					{
						sigAlgorithm = sigAlgs[idx];
						if (!writeToConsole)
							writeOutputFile(csvWriter, Integer.toString(confId) + ", " + displayID + ", TrustStore: " + sigAlgorithm);
						else
							System.out.println(confId + ", " + displayID + ", TrustStore: " + sigAlgorithm);
					}
				}
			}
		}
		catch (SQLException sqle)
		{
			ArcotLogger.logError("In CheckCertSigAlgorithm.checkCalloutCerts: Issue in Creating the CertificateConfig Cache",sqle);
			retValue = false;
		}
		catch (Exception e)
		{
			ArcotLogger.logError("In CheckCertSigAlgorithm.checkCalloutCerts: Issue in Creating the CertificateConfig Cache",e);
			retValue = false;
		}
		finally
		{
			try
			{
				if (rs != null)
					rs.close();

				if ( stmt != null )
					stmt.close();
			}
			catch ( SQLException sqle )
			{
				ArcotLogger.logError("In CheckCertSigAlgorithm.checkCalloutCerts: Issue in Creating the CertificateConfig Cache",sqle);
				retValue = false;
			}

			try
			{
				if(connection != null)
					connection.close();
				if(conn != null)
					new DBWrapper().releaseAdminConnection(conn);
				ArcotLogger.logInfo("In CheckCertSigAlgorithm.checkCalloutCerts: DB connection Released.");
			}
			catch(Exception e)
			{
				ArcotLogger.logError("In CheckCertSigAlgorithm.checkCalloutCerts: Error in closing DB connection", e);
				retValue = false;
			}
		}
		return retValue;
	}

    public static void main(String[] argv)
    {
		int rowsAffected = 0;
		int totalRowsAffected = 0;
        String csvFileName = "";
        String csvErrorFileName = "";
        boolean isInsert = true;
	    boolean encounterError = false;
        Writer csvWriter = null;
        CheckCertSigAlgorithm csaObj = new CheckCertSigAlgorithm();

		if (argv.length == 0)
			printUsage();

		if (argv.length == 1)
		{
		    if ("-s".equalsIgnoreCase(argv[0]))
		        csaObj.checkSigningCerts(null);
		    else if ("-c".equalsIgnoreCase(argv[0]))
		        csaObj.checkCalloutCerts(null);
		    else
				printUsage();
		}
		else if (argv.length == 3)
		{
		    if ("-s".equalsIgnoreCase(argv[0]) && "-o".equalsIgnoreCase(argv[1]))
		    {
				csvFileName = argv[2];
		        csaObj.checkSigningCerts(csvFileName);
			}
		    else if ("-c".equalsIgnoreCase(argv[0]) && "-o".equalsIgnoreCase(argv[1]))
		    {
				csvFileName = argv[2];
		        csaObj.checkCalloutCerts(csvFileName);
			}
		    else
				printUsage();
		}
		else
			printUsage();
	}
}
