package com.ca.nbiapps.certtool.dboperations;

import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Properties;

import com..crypto.CryptoUtil;
import com..database.DatabaseConnection;
import com..dboperations.DBHandler;
import com..logger.Logger;

public class DBWrapper extends DBHandler
{
	private String type = null;
	private String url = null;
	private String uid = null;
	private String pwd = null;
	private static Boolean initSuccess = false;

	static
	{
		try
		{
            System.loadLibrary("jni");
			//System.load("/Users/kussa01/Documents/System-Task/system_lib/libjni.so");
			try
			{
				CryptoUtil.initVPASCryptoUtil();
				initSuccess = true;
			}
			catch (Exception e)
			{
				e.printStackTrace();
				Logger.logError("Failed to init vpas crypto and thus cannot read the vpaspwd.ini", e);
			}
	    }
		catch (UnsatisfiedLinkError e)
		{
			e.printStackTrace();
			Logger.logError("Failed to load JNI. It might have been loaded by App server already. **** Ignore this error if dbConnType is set to JDBC ****", e);
		}
	    catch (Exception e)
	    {
	    	e.printStackTrace();
			Logger.logError("Failed to load JNI. It might have been loaded by App server already. **** Ignore this error if dbConnType is set to JDBC ****", e);
		}

    }

	public DBWrapper()
	{
		this.type = "ADMIN";
	}

	public DBWrapper(String url, String uid)
	{

		this.url = url;
		this.uid = uid;
		this.type = "TRANSFORT";

		if (initSuccess)
		    this.pwd = CryptoUtil.getKeyValue(uid, false);
	}

	public DBWrapper(String url, String uid, boolean softSign)
	{

		this.url = url;
		this.uid = uid;
		this.type = "TRANSFORT";

		if (initSuccess)
		{
			if (softSign == false)
			{
			    String device = "NCipher";
				String pin = CryptoUtil.getKeyValue("NCipher", true);
				int rc = CryptoUtil.InitSigner(pin, 8, "NCipher");

				if ( rc != 0 )
				{
				    pin = CryptoUtil.getKeyValue("nfast", true);
				    rc = CryptoUtil.InitSigner(pin, 8, "nfast");
				    if (rc != 0)
					    System.out.println("InitSigner() FAILED to execute, please check your hardware encryption configuration");
				}
			}

		    this.pwd = CryptoUtil.getKeyValue(uid, false);
		}
	}

	public DBWrapper(String url, String uid, String pwd)
	{
		this.url = url;
		this.uid = uid;
		this.pwd = pwd;
		this.type = "JDBC";
	}

	public void setConnectionType(String type)
	{
		this.type = type;
	}

	public DatabaseConnection getAdminConnection()
	{
		try
		{
	        return dbMan.getConnection();
	    }
	    catch (Exception e)
	    {
			Logger.logError("Failed to get JDBC connection", e);
		}

		return null;
	}

	public void releaseAdminConnection(DatabaseConnection conn)
	{
		try
		{
	        dbMan.release(conn);
	    }
	    catch (Exception e)
	    {
			Logger.logError("Failed to get JDBC connection", e);
		}

	}

	public Connection getConnection(Properties props)
	{
		try
		{
	        return DriverManager.getConnection(url, props);
	    }
	    catch (Exception e)
	    {
			Logger.logError("Failed to get JDBC connection", e);
		}

		return null;
	}

	public Connection getConnection()
	{
		try
		{
	        return DriverManager.getConnection(url, uid, pwd);
	    }
	    catch (Exception e)
	    {
			Logger.logError("Failed to get JDBC connection", e);
		}

		return null;
	}
}

