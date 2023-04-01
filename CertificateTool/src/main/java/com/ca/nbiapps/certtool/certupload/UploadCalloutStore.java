package com.ca.nbiapps.certtool.certupload;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.text.SimpleDateFormat;
import java.util.Enumeration;
import java.util.Properties;
import com.security.crypto.Base64;
import com.security.crypto.CryptoUtil;
import com.security.database.DatabaseConnection;
import com.security.logger.LoggerLog;
import com.ca.nbiapps.certtool.dboperations.DBWrapper;

import sun.security.pkcs.PKCS7;

public class UploadCalloutStore
{

	private boolean softEncrypt = false;
	private boolean jniInitized = false;
    private Properties prop = null;
    private Connection connection = null;
	private DatabaseConnection conn = null;
    private String connectionType = null;
    private String masterKey = null;
    private String originalKeyFileName = "";
    private String originalTrustFileName = "";
    private String keyStoreFileName = "";
    private String trustStoreFileName = "";
    private String trustStorePassPhrase = "";
    private int currentKeyStoreUploadCount = 0;
    private int currentTrustStoreUploadCount = 0;

    public UploadCalloutStore()
    {
        try
        {
            prop = new Properties();
			InputStream in = this.getClass().getResourceAsStream("/certsUpload.properties");
			if (in != null)
				LoggerLog.logInfo("In UploadCalloutStore: properties loaded");
			else
				LoggerLog.logError("In UploadCalloutStore: properties not loaded");
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
        System.out.println("\n\n1. Upload New Callout Key Store or Trust Store into the Database table");
        System.out.println("\nUploadCalloutStore <Store CSV Input File>");
        System.out.println("\nExample:");
        System.out.println("\njava UploadCalloutStore /home/stores/calloutStores.csv");
        System.out.println("\n\nKey Store or Trust Store CSV input format is like the following example:");
        System.out.println("\njava SSLConfigReport -d 7 -r IssuerSSLConfig\n\n");
        System.out.println("\n\n#Header columns for Input CSV file to upload KeyStore or TrustStore files");
		System.out.println("\n# Config_Name, KeyStore_Path_And_FileName, KeyStore_Pass_Phrase, TrustStore_Path_And_FileName, TrustStore_Pass_Phrase");
		System.out.println("\nDummy Callout1, /home/user/keystore1.jks,dost1234,,");
		System.out.println("\nDummy Callout2, /home/user/keystore2.p12,dost1234!,,");
		System.out.println("\nDummy Callout3,,, /home/user/truststore3.pfx,dost1@34");

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
			LoggerLog.logError("In UploadCalloutStore.initConnection: Cannot find JDBC Driver JAR file.", e);
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

		LoggerLog.logInfo("In UploadCalloutStore.initConnection: connectionType = " + connectionType);
		LoggerLog.logInfo("In UploadCalloutStore.initConnection: jdbcUrl = " + jdbcUrl);
		LoggerLog.logInfo("In UploadCalloutStore.initConnection: softEncrypt = " + softEncrypt);

		masterKey = prop.getProperty("encryptionKey");
		if (masterKey != null && !"".equals(masterKey))
            masterKey = new String(Base64.decode(masterKey));
	    else
	    {
			LoggerLog.logError("In UploadCalloutStore.initConnection: Cannot get MasterKey value from properties file.");
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
				LoggerLog.logInfo("In UploadCalloutStore.initConnection: Use TransFort DBHandler class to manage DB connections!");
                conn = new DBWrapper().getAdminConnection();
                if (conn == null)
                {
                    connectionType = "transfort";
					LoggerLog.logInfo("In UploadCalloutStore.initConnection: Failed with Admin connection. Use TransFort Type to connect.");
			    }
			    else
			        gotConnection = true;
		    }

 		    if (!gotConnection && connectionType != null && connectionType.equalsIgnoreCase("transfort"))
            {
				LoggerLog.logInfo("In UploadCalloutStore.initConnection: Use TransFort vpaspwd.ini settings to manage DB connections!");
                if (jdbcUrl.indexOf("PROTOCOL=tcps") != -1)
                    connection = new DBWrapper(jdbcUrl,dbuser).getConnection(props);
                else
                    connection = new DBWrapper(jdbcUrl,dbuser, softEncrypt).getConnection();

                if (connection != null)
			        gotConnection = true;
		    }

            if (!gotConnection)
            {
				LoggerLog.logInfo("In UploadCalloutStore.initConnection: Use JDBC driver connection to manage DB connections!");
                connection = new DBWrapper(jdbcUrl,dbuser,dbpasswd).getConnection();
                initResult = false;
            }
        }
        catch(Exception e)
        {
			LoggerLog.logError("In UploadCalloutStore.initConnection: Connection Failed!", e);
            initResult = false;
        }

        return initResult;
	}

    public static String convertInputStreamToString(InputStream inputStream) throws IOException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[10240];
        int length = 0;
        while ((length = inputStream.read(buffer)) != -1)
            baos.write(buffer, 0, length);

        return baos.toString();
    }

	public int runCommand(String command) throws IOException
	{
		LoggerLog.logInfo("In UploadCalloutStore.runCommand: Executing command - " + command);
		int returnValue = -1;
		try {
			Process process = Runtime.getRuntime().exec( command );
			process.waitFor();
			returnValue = process.exitValue();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

		return returnValue;
	}

	public String checkAndConvertCertType(String fileName, String passPhrase, boolean isKeyStore)
	{
		// if more than 1 store files are provided, then the number of password provided needs to be the same.
		// The format for multiple passwords will be of format: PASSWORD1:pwd=PASSWORD2:pwd=PASSWORD3....
		// eg. if 2 passwords are provided, it will look like dost1234:pwd=ABCD.
		// If store file is not PKCS12 or JKS and thus no password, then the prefix is still needed but value could be left blank.
		// e.g. dost1234:pwd=:pwd=LoggerLog
		int idx = 0;
		PKCS7 pkcs7 = null;
		FileInputStream fis = null;

		String[] storeFiles = fileName.split(":");
		String[] storePwds = passPhrase.split(":pwd=");
		int numFiles = storeFiles.length;
		int numPwds = storePwds.length;

		if (numFiles != numPwds)
		    return "NOPWD";

		if (numFiles == 1)
		{
			String certType = fileName.substring(fileName.lastIndexOf(".")+1);

			if ("P12".equalsIgnoreCase(certType) || "PFX".equalsIgnoreCase(certType))
				return "PKCS12";
			else if ("JKS".equalsIgnoreCase(certType))
				return "JKS";
		}

		// Multiple store files detected. Use the first file name as the JKS file name if conversion is needed.
		String fileNameBase = storeFiles[0].substring(storeFiles[0].lastIndexOf("/")+1, storeFiles[0].lastIndexOf("."));
		for (idx = 1;idx < numFiles;idx++)
			fileNameBase += "_" + storeFiles[idx].substring(storeFiles[idx].lastIndexOf("/")+1, storeFiles[idx].lastIndexOf("."));

		String jksFileName = fileNameBase + ".jks";
		String jksPassPhrase = storePwds[0];

		// Remove existing JKS file if any
		String cmdStr = "rm -rf " + jksFileName;
		try
		{
			if (runCommand(cmdStr) != 0)
			{
				LoggerLog.logError("In UploadCalloutStore.checkAndConvertCertType: Cannot remove the file: " + jksFileName);
				return "ERROR";
			}
		}
        catch (IOException e)
        {
			LoggerLog.logError("In UploadCalloutStore.checkAndConvertCertType: Cannot remove the file: " + jksFileName, e);
            return "ERROR";
        }
		LoggerLog.logInfo("In UploadCalloutStore.checkAndConvertCertType: Removing existing file: " + jksFileName);

		String certTypes[] = new String[numFiles];
		for (idx = 0;idx < numFiles;idx++)
		{
			certTypes[idx] = storeFiles[idx].substring(storeFiles[idx].lastIndexOf(".")+1);

			if (isKeyStore)
			{
				keyStoreFileName = jksFileName;
				originalKeyFileName = storeFiles[idx];
			}
			else
			{
				trustStoreFileName = jksFileName;
				trustStorePassPhrase = jksPassPhrase;
				originalTrustFileName = storeFiles[idx];
			}

			if ("P12".equalsIgnoreCase(certTypes[idx]) || "PFX".equalsIgnoreCase(certTypes[idx]))
			{
				certTypes[idx] = "PKCS12";

				// Import P12 to JKS
				cmdStr = "keytool -v -importkeystore -srckeystore " + storeFiles[idx] + " -srcstoretype PKCS12 -srcstorepass " + storePwds[idx] + " -destkeystore " + jksFileName + " -deststoretype JKS -deststorepass " + storePwds[0];
				try
				{
					if (runCommand(cmdStr) != 0)
					{
						LoggerLog.logError("In UploadCalloutStore.checkAndConvertCertType: Cannot import the file: " + storeFiles[idx] + " to file " + jksFileName);
						return "ERROR";
					}
				}
				catch (IOException e)
				{
					LoggerLog.logError("In UploadCalloutStore.checkAndConvertCertType: Cannot import the file: " + storeFiles[idx] + " to file " + jksFileName, e);
					return "ERROR";
				}
				LoggerLog.logInfo("In UploadCalloutStore.checkAndConvertCertType: Import " + certTypes[idx] + " format " + storeFiles[idx] + " to " + jksFileName + " file to be uploaded");

				continue;
			}
			else if ("JKS".equalsIgnoreCase(certTypes[idx]))
			{
				if (idx == 0)
				    continue;

				certTypes[idx] = "JKS";

				// Import JKS to JKS
				cmdStr = "keytool -v -importkeystore -srckeystore " + storeFiles[idx] + " -srcstoretype JKS -srcstorepass " + storePwds[idx] + " -destkeystore " + jksFileName + " -deststoretype JKS -deststorepass " + storePwds[0];
				try
				{
					if (runCommand(cmdStr) != 0)
					{
						LoggerLog.logError("In UploadCalloutStore.checkAndConvertCertType: Cannot import the file: " + storeFiles[idx] + " to file " + jksFileName);
						return "ERROR";
					}
				}
				catch (IOException e)
				{
					LoggerLog.logError("In UploadCalloutStore.checkAndConvertCertType: Cannot import the file: " + storeFiles[idx] + " to file " + jksFileName, e);
					return "ERROR";
				}
				LoggerLog.logInfo("In UploadCalloutStore.checkAndConvertCertType: Import " + certTypes[idx] + " format " + storeFiles[idx] + " to " + jksFileName + " file to be uploaded");

				continue;
			}

			// init certType to be empty string and check
			certTypes[idx] = "";

			try
			{
				fis = new FileInputStream(storeFiles[idx]);
				pkcs7 = new PKCS7(fis);
				certTypes[idx] = "PKCS7";
				fis.close();
				LoggerLog.logError("In UploadCalloutStore.checkAndConvertCertType: PKCS7 format is not supported and cannot be imported to " + jksFileName);

			    return certTypes[idx];

			}
			catch(Exception e)
			{
				//System.out.println("exception occurred");
				//e.printStackTrace();
			}

			if ("".equals(certTypes[idx]))
			{
				try
				{
					String certStr = convertInputStreamToString(new FileInputStream(storeFiles[idx]));
					if (certStr.indexOf("-----BEGIN CERTIFICATE-----") != -1)
						certTypes[idx] = "PEM";
					else
						certTypes[idx] = "DER";

					fis.close();

					try
					{
					    cmdStr = "keytool -importcert -file " + storeFiles[idx] + " -keystore " + jksFileName + " -storepass " + storePwds[idx] + " -storetype jks -alias " + storeFiles[idx] + " -noprompt";
						if (runCommand(cmdStr) != 0)
						{
							LoggerLog.logError("In UploadCalloutStore.checkAndConvertCertType: keytool import file: "  + storeFiles[idx] + " to " + jksFileName + "failed");
							return "ERROR";
						}
					}
					catch (IOException e)
					{
						LoggerLog.logError("In UploadCalloutStore.checkAndConvertCertType: keytool import file: "  + storeFiles[idx] + " to " + jksFileName + "failed", e);
						return "ERROR";
					}
					LoggerLog.logInfo("In UploadCalloutStore.checkAndConvertCertType: Convert " + certTypes[idx] + " format " + storeFiles[idx] + " to " + jksFileName + " file to be uploaded");

					certTypes[idx] = "JKS";
				}
				catch (Exception e) {
				}
			}
		}

		return "JKS";
	}

	public boolean checkStoreValidity(String fileName, String passPhrase, String bundleType, boolean isKeyStore)
	{
		boolean retValue = true;

		LoggerLog.logInfo("In UploadCalloutStore.checkStoreValidity: Check if " + fileName + " has valid format...");
		if (fileName == null || passPhrase == null || bundleType == null ||
		    "".equals(fileName) || "".equals(passPhrase) || "".equals(bundleType))
			return false;

		FileInputStream ios = null;
		KeyStore keyStore = null;

        try
        {
			if ("P12".equalsIgnoreCase(bundleType) || "PFX".equalsIgnoreCase(bundleType))
			{
				bundleType = "PKCS12";
				keyStore = KeyStore.getInstance("PKCS12");
			}
			else
			if ("JKS".equalsIgnoreCase(bundleType))
			{
				bundleType = "JKS";
				keyStore = KeyStore.getInstance("JKS");
			}
			else // check Certificate Type and convert PEM or DER format to JKS format if necessary
			{
				bundleType = checkAndConvertCertType(fileName, passPhrase, isKeyStore);
				if ("PKCS7".equalsIgnoreCase(bundleType))
				{
					LoggerLog.logError("In UploadCalloutStore.checkStoreValidity: PKCS7 format is not supported");
				    return false;
				}
				else if ("NOPWD".equalsIgnoreCase(bundleType))
				{
					LoggerLog.logError("In UploadCalloutStore.checkStoreValidity: The number of store files provided is not the same as the number of passwords provided.");
				    return false;
				}
				else if ("ERROR".equalsIgnoreCase(bundleType))
				{
					LoggerLog.logError("In UploadCalloutStore.checkStoreValidity: Ecounter I/O Error while executing keytool.");
				    return false;
				}
				else
				{
					keyStore = KeyStore.getInstance("JKS");

					if (isKeyStore && !"".equals(keyStoreFileName))
						fileName = keyStoreFileName;
					else
					if (!isKeyStore && !"".equals(trustStoreFileName))
						fileName = trustStoreFileName;
				}
			}

			LoggerLog.logError("In UploadCalloutStore.checkStoreValidity: Loading file " + fileName + " to JKS keystore");
			ios = new FileInputStream(fileName);
			if (isKeyStore)
				keyStore.load(ios, passPhrase.toCharArray());
			else
				keyStore.load(ios, passPhrase.split(":pwd=")[0].toCharArray());
		}
		catch(IOException e)
		{
			if (e.getCause() instanceof UnrecoverableKeyException)
				LoggerLog.logError("In UploadCalloutStore.checkStoreValidity: store passphrase might not be correct. Failure reason: " + e.getMessage());
			else
			{
				try
				{
					LoggerLog.logError("In UploadCalloutStore.checkStoreValidity: IOException Occurred. Failure reason: " + e.getMessage() + ". Continue check if it is different bundle type");
					// Try loading with different bundle type to verify if the store is of that type
					if ("PKCS12".equals(bundleType))
						keyStore = KeyStore.getInstance("JKS");
					else
						keyStore = KeyStore.getInstance("PKCS12");

		            //keyStore.load(ios, passPhrase.toCharArray());
		            keyStore.load(ios, null);
				}
				catch(IOException ex)
				{
					if (ex.getCause() instanceof UnrecoverableKeyException)
						Logger.logError("In UploadCalloutStore.checkStoreValidity: store passphrase might not be correct. Failure reason: " + ex.getMessage());
					else
					    Logger.logError("In UploadCalloutStore.checkStoreValidity: IOException Occurred. Failure reason: " + ex.getMessage());

					retValue = false;
				}
				catch(KeyStoreException ex)
				{
					Logger.logError("In UploadCalloutStore.checkStoreValidity: intended file is not valid " + bundleType + "Failure reason: " + ex.getMessage());
					retValue = false;
				}
				catch(NoSuchAlgorithmException ex)
				{
					Logger.logError("In UploadCalloutStore.checkStoreValidity: intended file is not valid " + bundleType + "Failure reason: " + ex.getMessage());
					retValue = false;
				}
				catch(CertificateException ex)
				{
					Logger.logError("In UploadCalloutStore.checkStoreValidity: intended file is not valid " + bundleType + "Failure reason: " + ex.getMessage());
					retValue = false;
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
						retValue = false;
					}
				}
			}
		}
		catch(KeyStoreException e)
		{
		    Logger.logError("In UploadCalloutStore.checkStoreValidity: intended file is not valid " + bundleType + "Failure reason: " + e.getMessage());
			retValue = false;
		}
		catch(NoSuchAlgorithmException e)
		{
		    Logger.logError("In UploadCalloutStore.checkStoreValidity: intended file is not valid " + bundleType + "Failure reason: " + e.getMessage());
			retValue = false;
		}
		catch(CertificateException e)
		{
		    Logger.logError("In UploadCalloutStore.checkStoreValidity: intended file is not valid " + bundleType + "Failure reason: " + e.getMessage());
			retValue = false;
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
			    Logger.logError("In UploadCalloutStore.checkStoreValidity: intended file is not valid " + bundleType + "Failure reason: " + ex2.getMessage());
				retValue = false;
			}
		}

	    Logger.logInfo("In UploadCalloutStore.checkStoreValidity: " + fileName + " has valid format!");
		return retValue;
	}

	public java.util.Date getLeastExpiryDate(String fileName, String passPhrase, String bundleType)
	{
	    Logger.logInfo("In UploadCalloutStore.getLeastExpiryDate: Get expiry date from file " + fileName);
		java.util.Date leastExpiryDate = null;
		FileInputStream ios = null;
		KeyStore keyStore = null;

        try
        {
			if ("P12".equals(bundleType)|| "p12".equals(bundleType) || "pfx".equals(bundleType) || "PFX".equals(bundleType))
				keyStore = KeyStore.getInstance("PKCS12");
			else
				keyStore = KeyStore.getInstance("JKS");

			ios = new FileInputStream(fileName);
            keyStore.load(ios, passPhrase.toCharArray());

			Enumeration<String> keyEnum = keyStore.aliases();
			String elem = null;
			while(keyEnum.hasMoreElements())
			{
				elem = (String)keyEnum.nextElement();
				if (keyStore.getCertificate(elem).getType().equals("X.509"))
				{
					if (leastExpiryDate == null && (((X509Certificate) keyStore.getCertificate(elem)).getNotAfter()).after(new java.util.Date()))
						leastExpiryDate = ((X509Certificate) keyStore.getCertificate(elem)).getNotAfter();
					else
					{
						if ((((X509Certificate) keyStore.getCertificate(elem)).getNotAfter()).before(leastExpiryDate) && (((X509Certificate) keyStore.getCertificate(elem)).getNotAfter()).after(new java.util.Date()))
							leastExpiryDate = ((X509Certificate) keyStore.getCertificate(elem)).getNotAfter();
					}
				}
			}
		}
		catch(IOException e)
		{
			if (e.getCause() instanceof UnrecoverableKeyException)
			    Logger.logError("In UploadCalloutStore.getLeastExpiryDate: store passphrase might not be correct. Failure reason: " + e.getMessage());
			else
			    Logger.logError("In UploadCalloutStore.getLeastExpiryDate: IOException Occurred. Failure reason: " + e.getMessage());
		}
		catch(KeyStoreException e)
		{
		    Logger.logError("In UploadCalloutStore.getLeastExpiryDate: intended file is not valid " + bundleType + "Failure reason: " + e.getMessage());
		}
		catch(NoSuchAlgorithmException e)
		{
		    Logger.logError("In UploadCalloutStore.getLeastExpiryDate: intended file is not valid " + bundleType + "Failure reason: " + e.getMessage());
		}
		catch(CertificateException e)
		{
		    Logger.logError("In UploadCalloutStore.getLeastExpiryDate: intended file is not valid " + bundleType + "Failure reason: " + e.getMessage());
		}
	    Logger.logInfo("In UploadCalloutStore.getLeastExpiryDate: Successfully get expiry date - " + leastExpiryDate + " from file " + fileName + "!");
		return leastExpiryDate;
	}

	public String getTimeStr(java.util.Date date)
	{
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy_MM_dd_HH_mm_ss");
        if (date == null)
            date = new java.util.Date();

        return dateFormat.format(date);
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

	public boolean getSoftEncrypt()
	{
		return softEncrypt;
	}

	public String getMasterKey()
	{
		return masterKey;
	}

	public String getOriginalKeyFileName()
	{
		return originalKeyFileName;
	}

	public String getOriginalTrustFileName()
	{
		return originalTrustFileName;
	}

	public String getKeyStoreFileName()
	{
		return keyStoreFileName;
	}

	public String getTrustStoreFileName()
	{
		return trustStoreFileName;
	}

	public String getTrustStorePassPhrase()
	{
		return trustStorePassPhrase;
	}

	public void resetOriginalKeyFileName()
	{
		originalKeyFileName = "";;
	}

	public void resetOriginalTrustFileName()
	{
		originalTrustFileName = "";;
	}

	public void resetKeyStoreFileName()
	{
		keyStoreFileName = "";
	}

	public void resetTrustStoreFileName()
	{
		trustStoreFileName = "";
	}

	public int getKeyStoreUploadCount()
	{
		return currentKeyStoreUploadCount;
	}

	public int getTrustStoreUploadCount()
	{
		return currentTrustStoreUploadCount;
	}

	public boolean isConfIDExist(String configIDStr)
	{
		boolean checkResult = false;
		ByteArrayInputStream bais = null;
        PreparedStatement pStmt = null;
        ResultSet rs = null;
		String selectConfIDStmt = "select ConfID from ARCALLOUTSSLCONFIG where ConfID = " + configIDStr;

		try
		{
			initConnection();

			if (connectionType != null && connectionType.equalsIgnoreCase("admin"))
				pStmt = conn.prepareStatement(selectConfIDStmt);
			else
				pStmt = connection.prepareStatement(selectConfIDStmt);

			rs = pStmt.executeQuery();

			if (rs.next())
			{
				checkResult = true;
				Logger.logInfo("In UploadCalloutStore.isConfIDExist: ConfID " + configIDStr + " already exist in ARCalloutSSLConfig table.");
			}
			else
				Logger.logError("In UploadCalloutStore.isConfIDExist: ConfID " + configIDStr + " does not exist in ARCalloutSSLConfig table.");
		}
		catch(Exception e)
		{
			Logger.logError("In UploadCalloutStore.isConfIDExist: SQL Failed!", e);
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
				Logger.logError("In UploadCalloutStore.isConfIDExist: Error in Final Block", e);
			}
			try
			{
				if(connection != null)
					connection.close();
				if(conn != null)
					new DBWrapper().releaseAdminConnection(conn);
				Logger.logInfo("In UploadCalloutStore.isConfIDExist: DB connection Released.");
			}
			catch(Exception e)
			{
				Logger.logError("In UploadCalloutStore.isConfIDExist: Error in closing DB connection", e);
			}
		}
		return checkResult;
	}

	public int getConfIDByConfName(String configName)
	{
		ByteArrayInputStream bais = null;
        PreparedStatement pStmt = null;
        ResultSet rs = null;
		String selectConfIDStmt = "select ConfID from ARCalloutsConfig where DisplayID = '" + configName + "'";
		int confid = -1;

		// check if this is for Silo Default
		if ("SILO_DEFAULT".equalsIgnoreCase(configName))
		    return 0;

		try
		{
			initConnection();

			if (connectionType != null && connectionType.equalsIgnoreCase("admin"))
				pStmt = conn.prepareStatement(selectConfIDStmt);
			else
				pStmt = connection.prepareStatement(selectConfIDStmt);

			rs = pStmt.executeQuery();

			if (rs.next())
				confid = rs.getInt(1);
			else
				Logger.logError("In UploadCalloutStore.getConfIDByConfName: Failed to execute query: " + selectConfIDStmt);
		}
		catch(Exception e)
		{
			Logger.logError("In UploadCalloutStore.getConfIDByConfName: SQL Failed!", e);
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
				Logger.logError("In UploadCalloutStore.getConfIDByConfName: Error in Final Block", e);
			}
			try
			{
				if(connection != null)
					connection.close();
				if(conn != null)
					new DBWrapper().releaseAdminConnection(conn);
				Logger.logInfo("In UploadCalloutStore.getConfIDByConfName: DB connection Released.");
			}
			catch(Exception e)
			{
				Logger.logError("In UploadCalloutStore.getConfIDByConfName: Error in closing DB connection", e);
			}
		}
		return confid;
	}

	public byte[] convertFiletoByteArray(String fileName)
	{
		byte[] bytesArray = null;
		try
		{
			File file = new File(fileName);

			//init array with file length
			bytesArray = new byte[(int) file.length()];
			FileInputStream fis = new FileInputStream(file);
			fis.read(bytesArray); //read file into bytes[]
			fis.close();
		}
		catch(Exception e)
		{
			Logger.logError("In UploadCalloutStore.convertFiletoByteArray: Loading " + fileName + " Failed:" + e.getMessage());
		}

		return bytesArray;
	}

	public int insertStoreFile(int confid, String adminName,
	                           String keyStoreFileName, String keyPassphrase, String keyBundleType, java.util.Date keyExpiryDate,
	                           String trustStoreFileName, String trustPassphrase, String trustBundleType, java.util.Date trustExpiryDate)
	{
		ByteArrayInputStream bais = null;
        PreparedStatement pStmt = null;
		int rowsAffected = 0;
		int colIdx = 2;

 		String insertStmt = "insert into ARCALLOUTSSLCONFIG (CONFID, KEYSTORE, KEYPASSPHRASE, KEYSTORETYPE, KEYSTOREEXPIRYDATE, PRECONFKEYID, MUTUALSSL, USEDEFAULTKEYSTORE, TRUSTSTORE, TRUSTPASSPHRASE, TRUSTSTORETYPE, TRUSTSTOREEXPIRYDATE, PRECONFTRUSTID, DATECREATED, UPLOADEDADMIN) values (?,";
 		if ("".equals(keyStoreFileName) || keyStoreFileName == null)
 		    insertStmt += "null,null,null,null,0,0,0,?,?,?,?,0,sysdate,?)";
 		else if ("".equals(trustStoreFileName) || trustStoreFileName == null)
 		    insertStmt += "?,?,?,?,0,?,0,null,null,null,null,0,sysdate,?)";
 		else
 		    insertStmt += "?,?,?,?,0,?,0,?,?,?,?,0,sysdate,?)";

        if ("p12".equals(keyBundleType)|| "P12".equals(keyBundleType) || "pfx".equals(keyBundleType) || "PFX".equals(keyBundleType))
            keyBundleType="PKC12";
        else
            keyBundleType="JKS";

        if ("p12".equals(trustBundleType)|| "P12".equals(trustBundleType) || "pfx".equals(trustBundleType) || "PFX".equals(trustBundleType))
            trustBundleType="PKC12";
        else
            trustBundleType="JKS";

		try
		{
			initConnection();

			if (connectionType != null && connectionType.equalsIgnoreCase("admin"))
				pStmt = conn.prepareStatement(insertStmt);
			else
				pStmt = connection.prepareStatement(insertStmt);

			pStmt.setQueryTimeout(10);
			pStmt.setInt(1, confid);

			String masterKeyLabel = getMasterKey();
			byte keyBundle[] = null;
			if (!"".equals(keyStoreFileName))
			    keyBundle = convertFiletoByteArray(keyStoreFileName);

			if (keyBundle != null)
			{
				currentKeyStoreUploadCount++;
			    bais = new ByteArrayInputStream(keyBundle);
    			pStmt.setBinaryStream(colIdx, bais, keyBundle.length);
    			pStmt.setString(colIdx+1, CryptoUtil.encrypt3DES64Ex(masterKeyLabel, keyPassphrase, softEncrypt, 0));
    			pStmt.setString(colIdx+2, keyBundleType);
 				pStmt.setDate(colIdx+3, new java.sql.Date(keyExpiryDate.getTime()));

 				// set mutual ssl to 1 except for silo default
			    if (confid > 0)
				    pStmt.setInt(colIdx+4, 1);
			    else
					pStmt.setInt(colIdx+4, 0); // SILO DEFAULT , not point in setting MUTUALSSL to 1

				if (bais != null)
					bais.close();

			    colIdx += 5;
			}

			byte trustBundle[] = null;
			if (!"".equals(trustStoreFileName))
			    trustBundle = convertFiletoByteArray(trustStoreFileName);

			if (trustBundle != null)
			{
				currentTrustStoreUploadCount++;
			    bais = new ByteArrayInputStream(trustBundle);
			    pStmt.setBinaryStream(colIdx, bais, trustBundle.length);
			    pStmt.setString(colIdx+1, CryptoUtil.encrypt3DES64Ex(masterKeyLabel, trustPassphrase, softEncrypt, 0));
    			pStmt.setString(colIdx+2, trustBundleType);
 				pStmt.setDate(colIdx+3, new java.sql.Date(trustExpiryDate.getTime()));
			    colIdx += 4;
			}

			pStmt.setString(colIdx, CryptoUtil.encrypt3DES64Ex(masterKeyLabel, adminName, softEncrypt, 0));

			rowsAffected = pStmt.executeUpdate();
			if (connectionType != null && !connectionType.equalsIgnoreCase("admin"))
				connection.commit();

			if (keyBundle != null)
			    Logger.logInfo("In UploadCalloutStore.insertStoreFile: Insert Key Store file suceess: [confid,truststoretype,uploadedadmin] = " + "[" + confid + "," + keyBundleType + "," + adminName + "]");

			if (trustBundle != null)
			    Logger.logInfo("In UploadCalloutStore.insertStoreFile: Insert Trust Store file suceess: [confid,truststoretype,uploadedadmin] = " + "[" + confid + "," + trustBundleType + "," + adminName + "]");

		}
		catch(Exception e)
		{
			Logger.logError("In UploadCalloutStore.insertStoreFile: SQL Failed!", e);
            return rowsAffected;
		}
		finally
		{
			try
			{
				if (pStmt != null)
					pStmt.close();
				if (bais != null)
					bais.close();
			}
			catch(Exception e)
			{
				Logger.logError("In UploadCalloutStore.insertStoreFile: Error in Final Block", e);
	            return rowsAffected;
			}
			try
			{
				if(connection != null)
					connection.close();
				if(conn != null)
					new DBWrapper().releaseAdminConnection(conn);
				Logger.logInfo("In UploadCalloutStore.insertStoreFile: DB connection Released.");
			}
			catch(Exception e)
			{
				Logger.logError("In UploadCalloutStore.insertStoreFile: Error in closing DB connection", e);
				return rowsAffected;
			}
		}
		return rowsAffected;
	}

	public int updateStoreFile(int confid, String adminName,
	                           String keyStoreFileName, String keyPassphrase, String keyBundleType, java.util.Date keyExpiryDate,
	                           String trustStoreFileName, String trustPassphrase, String trustBundleType, java.util.Date trustExpiryDate)
	{

		ByteArrayInputStream bais = null;
        PreparedStatement pStmt = null;
		int rowsAffected = 0;
		int colIdx = 1;

 		String updateStmt = "update ARCALLOUTSSLCONFIG set datecreated=sysdate, PRECONFTRUSTID=0, PRECONFKEYID=0, ";

 		if ("".equals(keyStoreFileName) || keyStoreFileName == null)
 		    updateStmt += "TRUSTSTORE=?, TRUSTPASSPHRASE=?, TRUSTSTORETYPE=?, TRUSTSTOREEXPIRYDATE=?, UPLOADEDADMIN=? where CONFID=?";
 		else if ("".equals(trustStoreFileName) || trustStoreFileName == null)
 		    updateStmt += "KEYSTORE=?, KEYPASSPHRASE=?, KEYSTORETYPE=?, KEYSTOREEXPIRYDATE=?, MUTUALSSL=?, UPLOADEDADMIN=? where CONFID=?";
 		else
 		    updateStmt += "KEYSTORE=?, KEYPASSPHRASE=?, KEYSTORETYPE=?, KEYSTOREEXPIRYDATE=?, MUTUALSSL=?, TRUSTSTORE=?, TRUSTPASSPHRASE=?, TRUSTSTORETYPE=?, TRUSTSTOREEXPIRYDATE=?, UPLOADEDADMIN=? where CONFID=?";

        if ("p12".equals(keyBundleType)|| "P12".equals(keyBundleType) || "pfx".equals(keyBundleType) || "PFX".equals(keyBundleType))
            keyBundleType="PKC12";
        else
            keyBundleType="JKS";

        if ("p12".equals(trustBundleType)|| "P12".equals(trustBundleType) || "pfx".equals(trustBundleType) || "PFX".equals(trustBundleType))
            trustBundleType="PKC12";
        else
            trustBundleType="JKS";


		try
		{
			initConnection();

			if (connectionType != null && connectionType.equalsIgnoreCase("admin"))
				pStmt = conn.prepareStatement(updateStmt);
			else
				pStmt = connection.prepareStatement(updateStmt);

			pStmt.setQueryTimeout(10);

			String masterKeyLabel = getMasterKey();
			byte keyBundle[] = null;
			if (!"".equals(keyStoreFileName))
			    keyBundle = convertFiletoByteArray(keyStoreFileName);

			if (keyBundle != null)
			{
				currentKeyStoreUploadCount++;
			    bais = new ByteArrayInputStream(keyBundle);
			    pStmt.setBinaryStream(colIdx, bais, keyBundle.length);
			    pStmt.setString(colIdx+1, CryptoUtil.encrypt3DES64Ex(masterKeyLabel, keyPassphrase, softEncrypt, 0));
			    pStmt.setString(colIdx+2, keyBundleType);
			    pStmt.setDate(colIdx+3, new java.sql.Date(keyExpiryDate.getTime()));

			    if (confid > 0)
			        pStmt.setInt(colIdx+4, 1);
			    else
			        pStmt.setInt(colIdx+4, 0); // SILO DEFAULT , not point in setting MUTUALSSL to 1

				if (bais != null)
					bais.close();

			    colIdx += 5;
			}

			byte trustBundle[] = null;
			if (!"".equals(trustStoreFileName))
			    trustBundle = convertFiletoByteArray(trustStoreFileName);

			if (trustBundle != null)
			{
				currentTrustStoreUploadCount++;
			    bais = new ByteArrayInputStream(trustBundle);
			    pStmt.setBinaryStream(colIdx, bais, trustBundle.length);
			    pStmt.setString(colIdx+1, CryptoUtil.encrypt3DES64Ex(masterKeyLabel, trustPassphrase, softEncrypt, 0));
			    pStmt.setString(colIdx+2, trustBundleType);
			    pStmt.setDate(colIdx+3, new java.sql.Date(trustExpiryDate.getTime()));
			    colIdx += 4;
			}

			pStmt.setString(colIdx, CryptoUtil.encrypt3DES64Ex(masterKeyLabel, adminName, softEncrypt, 0));
			pStmt.setInt(colIdx+1, confid);

			rowsAffected = pStmt.executeUpdate();
			if (connectionType != null && !connectionType.equalsIgnoreCase("admin"))
				connection.commit();

			if (keyBundle != null)
			    Logger.logInfo("In UploadCalloutStore.updateStoreFile: Update Key Store file suceess: [confid,truststoretype,uploadedadmin] = " + "[" + confid + "," + keyBundleType + "," + adminName + "]");

			if (trustBundle != null)
			    Logger.logInfo("In UploadCalloutStore.updateStoreFile: Update Trust Store file suceess: [confid,truststoretype,uploadedadmin] = " + "[" + confid + "," + trustBundleType + "," + adminName + "]");

		}
		catch(Exception e)
		{
			Logger.logError("In UploadCalloutStore.updateStoreFile: SQL Failed!", e);
            return rowsAffected;
		}
		finally
		{
			try
			{
				if (pStmt != null)
					pStmt.close();
				if (bais != null)
					bais.close();
			}
			catch(Exception e)
			{
				Logger.logError("In UploadCalloutStore.updateStoreFile: Error in Final Block", e);
	            return rowsAffected;
			}
			try
			{
				if(connection != null)
					connection.close();
				if(conn != null)
					new DBWrapper().releaseAdminConnection(conn);
				Logger.logInfo("In UploadCalloutStore.updateStoreFile: DB connection Released.");
			}
			catch(Exception e)
			{
				Logger.logError("In UploadCalloutStore.updateStoreFile: Error in closing DB connection", e);
				return rowsAffected;
			}
		}
		return rowsAffected;
	}

	public void writeErrorCSV(Writer csvWriter, String csvLine, String reason)
	{
		try
		{
		    csvWriter.write(csvLine + ", " + reason + "\n");
		}
		catch(Exception e)
		{
			System.out.println(getLogTimeHeader(null) + "In UploadCalloutStore.writeErrorCSV: Error occurred during output of upload error. Reason: " + e.getMessage());
		}
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
        UploadCalloutStore ucsObj = null;

		if (argv.length == 0)
			printUsage();

		if (argv.length == 1)
		{
		    if ("-h".equalsIgnoreCase(argv[0]))
		        printUsage();
		    else
				csvFileName = argv[0];
		}
		else
			printUsage();



        BufferedReader br = null;
        String line = "";
        String delimiter = ",";

        try
        {
            ucsObj = new UploadCalloutStore();
			csvErrorFileName = csvFileName.substring(0, csvFileName.indexOf(".csv")) + "_Error_" + ucsObj.getTimeStr(null) + ".csv";

			csvWriter = new FileWriter(csvErrorFileName);
            br = new BufferedReader(new FileReader(csvFileName));

            // Read the input CSV file and upload store files one at a time
            while ((line = br.readLine()) != null)
            {
				line = line.replace("\n", "");

				// skip the empty or comment lines
				if (line.length() == 0 || line.charAt(0) == '#')
				    continue;

                // use comma as separator
                String[] storeInfo = line.split(delimiter, -1);
                int storeLen = storeInfo.length;
				String configName = (storeLen >= 1 ? storeInfo[0].trim() : "");
				String keyStoreFile = (storeLen >= 2 ? storeInfo[1].trim() : "");
				String keyStorePassPhrase = (storeLen >= 3 ? storeInfo[2].trim() : "");
				String trustStoreFile = (storeLen >= 4 ? storeInfo[3].trim() : "");
				String trustStorePassPhrase = (storeLen >= 5 ? storeInfo[4].trim() : "");

				// In case there are more than 1 files for trust store
				String trustStoreFiles[] = trustStoreFile.split(":");

				// mask the pass phrases
				if (storeLen == 0)
				    line = "";
				if (storeLen >= 1)
				    line = configName;
				if (storeLen >= 2)
				    line += "," +  keyStoreFile;
				if (storeLen >= 3)
				    line += ",********,";
				if (storeLen >= 4)
				    line += trustStoreFile;
				if (storeLen >= 5)
				    line += ",********";
				if (storeLen >= 6)
				    line += "," + storeInfo[5].trim() + ",....";

                if (storeInfo.length != 5)
                {
				    Logger.logError("In UploadCalloutStore.main: CSV line error. the input line must have exactly 5 columns:" + line);
					System.out.println(ucsObj.getLogTimeHeader(null) + "In UploadCalloutStore.main: CSV line error. the input line must have exactly 5 columns:" + line);
					ucsObj.writeErrorCSV(csvWriter, line, "CSV line error. The input line must have exactly 5 columns.");
					continue;
				}

				Logger.logInfo("In UploadCalloutStore.main: [configName, keyStoreFile, keyStorePassPhrase, trustStoreFile, trustStorePassPhrase] = [" + configName + "," + keyStoreFile + ",********," + trustStoreFile + ",********]");

				boolean isKeystoreExist = (keyStoreFile != null && !"".equals(keyStoreFile));
				boolean isTruststoreExist = (trustStoreFile != null && !"".equals(trustStoreFile));

				// Make sure at least one store file is available
				if (!isKeystoreExist && !isTruststoreExist)
				{
				    Logger.logError("In UploadCalloutStore.main: No store file in the input CSV line.");
				    System.out.println(ucsObj.getLogTimeHeader(null) + "In UploadCalloutStore.main: No store file in the input CSV line.");
				    ucsObj.writeErrorCSV(csvWriter, line, "No Keystore or Truststore file is given");
				    encounterError = true;
				    continue;
				}

				// check if physical Key Store file exists
				if (isKeystoreExist)
				{
					File keyStoreFileHandle = new File(keyStoreFile);
					if (!keyStoreFileHandle.exists() || keyStoreFileHandle.isDirectory())
					{
						Logger.logError("In UploadCalloutStore.main: Keystore File " + keyStoreFile + " does not exist or is a directory. Upload is not performed for this file.");
						System.out.println(ucsObj.getLogTimeHeader(null) + "In UploadCalloutStore.main: Keystore File " + keyStoreFile + " does not exist or is a directory. Upload is not performed for this file.");
						ucsObj.writeErrorCSV(csvWriter, line, "Keystore file does not exist or is a directory");
					    encounterError = true;
						continue;
					}
			    }

				// check if physical Trust Store file exists
				if (isTruststoreExist)
				{
					for (int idx = 0;idx < trustStoreFiles.length;idx++)
					{
						File trustStoreFileHandle = new File(trustStoreFiles[idx]);
						if (!trustStoreFileHandle.exists() || trustStoreFileHandle.isDirectory())
						{
							Logger.logError("In UploadCalloutStore.main: Truststore File " + trustStoreFiles[idx] + " does not exist or is a directory. Upload is not performed for this file.");
							System.out.println(ucsObj.getLogTimeHeader(null) + "In UploadCalloutStore.main: Truststore File " + trustStoreFiles[idx] + " does not exist or is a directory. Upload is not performed for this file.");
							ucsObj.writeErrorCSV(csvWriter, line, "Truststore file does not exist or is a directory");
						    encounterError = true;
						    continue;
						}
					}
			    }

				// Check if the store file is valid
				if (isKeystoreExist && !ucsObj.checkStoreValidity(keyStoreFile, keyStorePassPhrase, keyStoreFile.substring(keyStoreFile.lastIndexOf(".")+1), true))
				{
				    Logger.logError("In UploadCalloutStore.main: " + keyStoreFile + " is not a valid Keystore file. Upload is not performed for this file.");
				    System.out.println(ucsObj.getLogTimeHeader(null) + "In UploadCalloutStore.main: " + keyStoreFile + " is not a valid Keystore file. Upload is not performed for this file.");
				    ucsObj.writeErrorCSV(csvWriter, line, "Keystore file or pass phrase is not valid");
				    encounterError = true;
				    continue;
				}

				if (isKeystoreExist && !"".equals(ucsObj.getKeyStoreFileName()))
				{
					keyStoreFile = ucsObj.getKeyStoreFileName();
					ucsObj.resetKeyStoreFileName();
				}

				// Check if the store file is valid
				if (isTruststoreExist &&
					((trustStoreFiles.length == 1 && !ucsObj.checkStoreValidity(trustStoreFile, trustStorePassPhrase, trustStoreFile.substring(trustStoreFile.lastIndexOf(".")+1), false)) ||
				     (trustStoreFiles.length > 1 && !ucsObj.checkStoreValidity(trustStoreFile, trustStorePassPhrase, "MULTI", false))))
				{
					if (trustStoreFiles.length == 1)
					{
						Logger.logError("In UploadCalloutStore.main: " + trustStoreFile + " is not a valid Trsutstore file. Upload is not performed for this file.");
						System.out.println(ucsObj.getLogTimeHeader(null) + "In UploadCalloutStore.main: " + trustStoreFile + " is not a valid Trsutstore file. Upload is not performed for this file.");
					}
					else
					{
						Logger.logError("In UploadCalloutStore.main: At least one of the file in " + trustStoreFile + " is not a valid Trsutstore files. Upload is not performed for these files.");
						System.out.println(ucsObj.getLogTimeHeader(null) + "In UploadCalloutStore.main: At least one of the file in " + trustStoreFile + " is not a valid Trsutstore files. Upload is not performed for these files.");
					}

				    ucsObj.writeErrorCSV(csvWriter, line, "Truststore file or pass phrase is not valid");
				    encounterError = true;
				    continue;
				}

				Logger.logInfo("In UploadCalloutStore.main: ucsObj.getTrustStoreFileName() = " + ucsObj.getTrustStoreFileName());
				if (isTruststoreExist && !"".equals(ucsObj.getTrustStoreFileName()))
				{
					trustStoreFile = ucsObj.getTrustStoreFileName();
					trustStorePassPhrase = ucsObj.getTrustStorePassPhrase();
					ucsObj.resetTrustStoreFileName();
				}

				java.util.Date keyExpiryDate = null;
				java.util.Date trustExpiryDate = null;

				// Extract the expiry date from the Keystore file
				if (isKeystoreExist)
				   keyExpiryDate = ucsObj.getLeastExpiryDate(keyStoreFile, keyStorePassPhrase, keyStoreFile.substring(keyStoreFile.lastIndexOf(".")+1));

				Logger.logInfo("In UploadCalloutStore.main: keyExpiryDate = " + keyExpiryDate);
				
				if (isTruststoreExist)
				   trustExpiryDate = ucsObj.getLeastExpiryDate(trustStoreFile, trustStorePassPhrase, trustStoreFile.substring(trustStoreFile.lastIndexOf(".")+1));

				Logger.logInfo("In UploadCalloutStore.main: trustExpiryDate = " + trustExpiryDate);
				// Look up configuration id using the configuration name
				int confid = ucsObj.getConfIDByConfName(configName);
				Logger.logInfo("In UploadCalloutStore.main: confid = " + confid);
				if (confid == -1)
				{
					if (isKeystoreExist)
					{
				    	Logger.logError("In UploadCalloutStore.main: " + configName + " does not exist in the current callout configuration. Keystore file " + keyStoreFile + " will not be uploaded.");
				    	System.out.println(ucsObj.getLogTimeHeader(null) + "In UploadCalloutStore.main: " + configName + " does not exist in the current callout configuration. Keystore file " + keyStoreFile + " will not be uploaded.");
					}

					if (isTruststoreExist)
					{
				    	Logger.logError("In UploadCalloutStore.main: " + configName + " does not exist in the current callout configuration. Keystore file " + trustStoreFile + " will not be uploaded.");
				    	System.out.println(ucsObj.getLogTimeHeader(null) + "In UploadCalloutStore.main: " + configName + " does not exist in the current callout configuration. Keystore file " + trustStoreFile + " will not be uploaded.");
					}
				    ucsObj.writeErrorCSV(csvWriter, line, "Callout Configuration does not exist");
				    encounterError = true;
				    continue;
				}

				// check if ConfID already exist or not
				isInsert = !ucsObj.isConfIDExist(Integer.toString(confid));
				Logger.logInfo("In UploadCalloutStore.main: isInsert = " + isInsert);
				if (isInsert)
					rowsAffected = ucsObj.insertStoreFile(confid,
					                "CertUpload_Admin",
					                keyStoreFile,
					                keyStorePassPhrase,
					                keyStoreFile.substring(keyStoreFile.lastIndexOf(".")+1),
					                keyExpiryDate,
					                trustStoreFile,
					                trustStorePassPhrase,
					                trustStoreFile.substring(trustStoreFile.lastIndexOf(".")+1),
					                trustExpiryDate);
				else
					rowsAffected = ucsObj.updateStoreFile(confid,
					                "CertUpload_Admin",
					                keyStoreFile,
					                keyStorePassPhrase,
					                keyStoreFile.substring(keyStoreFile.lastIndexOf(".")+1),
					                keyExpiryDate,
					                trustStoreFile,
					                trustStorePassPhrase,
					                trustStoreFile.substring(trustStoreFile.lastIndexOf(".")+1),
					                trustExpiryDate);

				if (rowsAffected == 1)
				{
					if (isKeystoreExist)
					{
						Logger.logInfo("In UploadCalloutStore.main: " + configName + " with Keystore file " + keyStoreFile + " uploaded successfully!");
						System.out.println(ucsObj.getLogTimeHeader(null) + "In UploadCalloutStore.main: " + configName + " with Keystore file " + keyStoreFile + " uploaded successfully!");
					}

					if (isTruststoreExist)
					{
						String logMsg = "In UploadCalloutStore.main: " + configName + " with Trsutstore file(s) " + trustStoreFiles[0];
						for (int idx = 1;idx < trustStoreFiles.length-1;idx++)
						    logMsg += ", " + trustStoreFiles[idx];
						logMsg += " and " + trustStoreFiles[trustStoreFiles.length-1] + " uploaded successfully!";
						Logger.logInfo(logMsg);
						System.out.println(ucsObj.getLogTimeHeader(null) + logMsg);
					}
				}
			    else
			    {
					if (isKeystoreExist)
					{
						Logger.logInfo("In UploadCalloutStore.main: " + configName + " with Keystore file " + keyStoreFile + " failed to be uploaded.");
						System.out.println(ucsObj.getLogTimeHeader(null) + "In UploadCalloutStore.main: " + configName + " with Keystore file " + keyStoreFile + " failed to be uploaded.");
					}

					if (isTruststoreExist)
					{
						String logMsg = "In UploadCalloutStore.main: " + configName + " with Trsutstore file(s) " + trustStoreFiles[0];
						for (int idx = 1;idx < trustStoreFiles.length-1;idx++)
						    logMsg += ", " + trustStoreFiles[idx];
						logMsg += " and " + trustStoreFiles[trustStoreFiles.length-1] + " failed to be uploaded.";
						Logger.logInfo(logMsg);
						System.out.println(ucsObj.getLogTimeHeader(null) + logMsg);
					}
				}

			    totalRowsAffected += rowsAffected;

			    // Check if any certificate conversion was done. If yes, then remove the newly created JKS file.
			    if (isKeystoreExist && !"".equals(ucsObj.getOriginalKeyFileName()))
			    {
					String cmdStr = "rm -rf " + keyStoreFile;
					ucsObj.runCommand(cmdStr);
					ucsObj.resetOriginalKeyFileName();
					Logger.logInfo("In UploadCalloutStore.main: Removing newly created JKS file after upload: " + keyStoreFile);
				}

			    if (isTruststoreExist && !"".equals(ucsObj.getOriginalTrustFileName()))
			    {
					String cmdStr = "rm -rf " + trustStoreFile;
					ucsObj.runCommand(cmdStr);
					ucsObj.resetOriginalTrustFileName();
					Logger.logInfo("In UploadCalloutStore.main: Removing newly created JKS file after upload: " + trustStoreFile);
				}

            } // while

			Logger.logInfo("In UploadCalloutStore.main: " + totalRowsAffected + " total rows are uploaded successfully including " + ucsObj.getTrustStoreUploadCount() + " Truststores and " + ucsObj.getKeyStoreUploadCount() + " Keystores.");
			System.out.println("\n\n" + ucsObj.getLogTimeHeader(null) + "In UploadCalloutStore.main: " + totalRowsAffected + " total rows are uploaded successfully including " + ucsObj.getTrustStoreUploadCount() + " Truststores and " + ucsObj.getKeyStoreUploadCount() + " Keystores.");
        }
        catch (FileNotFoundException e)
        {
            e.printStackTrace();
		    ucsObj.writeErrorCSV(csvWriter, "FileNotFoundException caught - Reason: ", e.getMessage());
		    encounterError = true;
        }
        catch (IOException e)
        {
            e.printStackTrace();
		    ucsObj.writeErrorCSV(csvWriter, "IOException caught - Reason", e.getMessage());
		    encounterError = true;
        }
		catch (Exception e)
		{
			Logger.logError("Error before Final Block", e);
		    ucsObj.writeErrorCSV(csvWriter, "Exception caught - Reason", e.getMessage());
		    encounterError = true;
		}
        finally
        {
            if (br != null)
            {
                try
                {
                    br.close();
                }
                catch (IOException e)
                {
                    e.printStackTrace();
                }
            }

			try
			{
				if (csvWriter != null)
					csvWriter.close();
			}
			catch (Exception e)
			{
				Logger.logError("Error before Final Block", e);
			}
        }

        if (encounterError)
        {
			Logger.logInfo("In UploadCalloutStore.main: Error Occurred during upload. Please check " + csvErrorFileName + " to view the store files that failed to be uploaded.");
			System.out.println(ucsObj.getLogTimeHeader(null) + "In UploadCalloutStore.main: Error Occurred during upload. Please check " + csvErrorFileName + "to view the store files that failed to be uploaded.");
		}
	}
}
