package edu.csus.jhe2.simplepasswordmanager;

import java.io.Console;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;
import javax.swing.JTextArea;

public class SimplePasswordManager 
{
	private static boolean showDebug = false;
	private static boolean isPasswordInputVisable = false;
	
	private final String ADDRESS = "jdbc:sqlite:database.db";
	private Connection con;
	
	private Console console;
	private Scanner scanner;
	
	private String currentUser = "";
	private String userTableID = "";
	
	public static void main(String[] args)	
	{ 
		for (String arg : args)
		{
			switch (arg.toLowerCase())
			{
				case "-debug":
					showDebug = true;
					break;
					
				case "-showpassword":
					isPasswordInputVisable = true;
					break;
					
				default:
					break;
			}
		}
		
		new SimplePasswordManager(); 
	}
	
	private void endProgram()
	{
		System.out.println("\nSimple Password Manager is now exiting.\n");
		
		scanner.close();
		System.exit(0);
	}
	
	public SimplePasswordManager()
	{
		System.out.println("\n----- Program starting up. -----");
		
		// Initialize things
		if (!isPasswordInputVisable)
		{
			console = System.console();
			if (console == null)
			{
				System.out.println("No console found. Shutting down."
						+ "\nIf you wish to use a incompatable console, add '-showpassword' to the start command.");
				return;
			}
		}
		
		scanner = new Scanner(System.in);
		
		boolean databaseExists = (new File("database.db")).exists();
		if (!databaseExists)
			System.out.println("Database file does not exist. A new one will be created.");
		
		if (!dbConnect())
		{
			System.out.println("[ERROR] Unable to open database. Shutting down.");
			System.out.println("");
			System.exit(0);
		}
		else
		{
			System.out.println("[Info] Database connection test is a success.");
		}
		
		if (!databaseExists)
		{
			try
			{
				PreparedStatement st = this.con.prepareStatement(
						"CREATE TABLE accounts (user TEXT PRIMARY KEY, password TEXT, tableID TEXT);");
				dbUpdate(st);
			} catch (SQLException e) { printErrorMessage(e); }
		}
		
		dbDisconnect();
		
		// Initialize done
		
		System.out.println("----- Start up complete. -----\n"
				+ "\nWelcome to Simple Password Manager.");
		
		String response = "";
		boolean validResponse = false;
		boolean newUser = false;
		
		do
		{
			System.out.print("\nAre you a new user? (Y/N): ");
			response = getUserInput();
			
			if (response.equalsIgnoreCase("y") || response.equalsIgnoreCase("n"))
			{
				validResponse = true;
				newUser = response.equalsIgnoreCase("y");
			}
			else
			{
				System.out.print("- Notice: Invalid response. \nPlease respond with Y or N.");
			}
		} while (!validResponse);
		
		if (newUser)
			registerNewUser();
		else
			loginExistingUser();
		
		boolean done = false;
		
		System.out.println("\nWelcome " + currentUser + ".");
		
		while (!done)
		{
			// Show menu
			int count = 0;
			StringBuilder sb = new StringBuilder();
			List<String> availServices = getServices();
			for (String s : availServices)
			{
				if (count >= 5)
				{
					sb.append("\n");
					count = 0;
				}
				
				sb.append(s + ", ");
				
				count++;
			}
			
			if (sb.length() > 2)
				sb.deleteCharAt(sb.length() - 2);
			
			System.out.print("\n==========================================================================="
					+ "\n"
					+ "\nFollowing services have a password stored in this manager: "
					+ "\n" + sb.toString()
					+ "\n"
					+ "\n---------------------------------------------------------------------------"
					+ "\n"
					+ "\nOptions (service is case-sensitive):"
					+ "\nNew (service) | Get (service) | Delete (service) | Quit"
					+ "\n"
					+ "\nEnter a option: ");
			response = getUserInput();
			
			System.out.println("");
			
			String[] input = response.split(" ");
			switch (input[0].toLowerCase())
			{
				case "new":
					newServiceEntry(input);
					break;
				
				case "get":
					getServiceEntry(input);
					break;
					
				case "delete":
					deleteServiceEntry(input);
					break;
					
				case "quit":
					done = true;
					break;
					
				default:
					System.out.println("Invalid option entered. Try again.");
					break;
			}
			
			if (!input[0].toLowerCase().equals("quit"))
				pauseTillEnter();
		}
		
		endProgram();
	}
	
	private void registerNewUser()
	{
		String response = "";
		String user = "", password = "", tableID = "";
		
		// Pick username		
		System.out.println("\nPlease select a username. Note: Username is not case-sensitive.");
		System.out.print("Enter a username: ");
		response = getUserInput();
		
		boolean valid = false;
		
		while (!valid)
		{
			if (!validInput(response))
			{
				System.out.println("- Notice: Invalid characters in provided username.");
				System.out.print("Enter a different username you wish to use: ");
				response = getUserInput();
			}
			else if (userExist(response))
			{
				System.out.print("- Notice: Username is already taken. \nPlease choose another username: ");
				response = getUserInput();
			}
			else
			{
				valid = true;
				user = response.toLowerCase(); //Stores every username lowercase to prevent dupes
			}
		}
		
		// Pick password
		valid = false;
		
		if (isPasswordInputVisable)
		{
			System.out.print("Enter the password you wish to use (case-sensitive): ");
			response = getUserInput();
		}
		else
		{
			char[] pwArray = console.readPassword("Enter the password you wish to use (case-sensitive): ");
			response = new String(pwArray);
		}
		
		while (!valid)
		{
			if (validInput(response) && response.length() >= 5)
			{
				valid = true;
				password = hashString(response);
			}
			else
			{
				System.out.println("The password you've provided contains invalid characters or is too short.");
				
				if (isPasswordInputVisable)
				{
					System.out.print("Enter the password you wish to use (case-sensitive): ");
					response = getUserInput();
				}
				else
				{
					char[] pwArray = console.readPassword("Enter the password you wish to use (case-sensitive): ");
					response = new String(pwArray);
				}
			}
		}
		
		// Generate tableID
		valid = false;
		
		while (!valid)
		{
			tableID = UUID.randomUUID().toString();
			
			if (!tableIDExist(response))
				valid = true;
		}
		
		addNewUser(user, password, tableID);
		currentUser = user;
		userTableID = tableID;
		
		if (userExist(currentUser))
		{
			System.out.println("-- Account successfully created --");
			pauseTillEnter();
		}
		else
		{
			System.out.println("Account not made due to error. Ending password manager.");
			endProgram();
		}
	}
	
	private void loginExistingUser()
	{
		String response = "";
		boolean validResponse = false;
		
		System.out.print("Enter your username: ");
		response = getUserInput();
		
		// Check if user exist
		while (!validResponse)
		{
			if (!userExist(response))
			{
				System.out.println("- Notice: Username not found. "
						+ "If you wish to create an account with the provided username, please restart the program.");
				System.out.print("Enter your username: ");
				response = getUserInput();
			}
			else
			{
				validResponse = true;
				currentUser = response;
			}
		}
		
		
		// Ask and check password
		validResponse = false;
		char[] pwArray;
		int attemptsLeft = 3;
		
		if (isPasswordInputVisable)
		{
			System.out.print("Enter your password: ");
			response = getUserInput();
		}
		else
		{
			pwArray = console.readPassword("Enter your password: ");
			response = new String(pwArray);
		}
		
		while (!validResponse)
		{
			if (!passwordMatch(currentUser, hashString(response)))
			{
				attemptsLeft--;
				
				if (attemptsLeft > 0)
				{
					if (isPasswordInputVisable)
					{
						System.out.print("- Notice: Incorrect password given. Attempts left: " + (attemptsLeft) 
								+"\nEnter your password: ");
						response = getUserInput();
					}
					else
					{
						pwArray = console.readPassword("- Notice: Incorrect password given. Attempts left: " + (attemptsLeft) 
								+"\nEnter your password: ");
						response = new String(pwArray);
					}
				}
				else
				{
					System.out.println("- Notice: Too many password attempts. Closing password manager.");
					endProgram();
				}
			}
			else
			{
				validResponse = true;
			}
		}
		
		this.userTableID = getUserTableID(currentUser);
		
		System.out.println("-- Sign-in Success --");
		pauseTillEnter();
	}
	
	private void newServiceEntry(String[] input)
	{
		String serviceName = getServiceName(input);
		if (serviceName.equals(""))
		{
			System.out.println("No service name provided. Please include the service name when entering a option.");
			return;
		}
		
		String username = "";
		String password = "";
		String key = "";
		
		System.out.print("Enter the username for " + serviceName + ": ");
		username = getUserInput();
		
		if (isPasswordInputVisable)
		{
			System.out.print("Enter the password for " + serviceName + ": ");
			password = getUserInput();
		}
		else
		{
			char[] pwArray = console.readPassword("Enter the password for " + serviceName + ": ");
			password = new String(pwArray);
		}
		
		System.out.print("Enter a encryption key (case-sensitive): ");
		key = getUserInput();
		
		username = encrypt(username, key);
		password = encrypt(password, key);
		key = hashString(key);
		
		addNewService(serviceName, username, password, key);
		
		System.out.println("Credentials for " + serviceName + " has been added.");
	}
	
	private void getServiceEntry(String[] input)
	{
		String serviceName = getServiceName(input);
		if (serviceName.equals(""))
		{
			System.out.println("No service name provided. Please include the service name when entering a option.");
			return;
		}
		
		if (!isService(serviceName))
		{
			System.out.println("The service you've enter does not have a stored password. "
					+ "(Service name needs to be case-sensitive)");
			return;
		}
		
		String key = "";
		
		System.out.println("Now getting the password for " + serviceName + ".");
		System.out.print("Enter decrpytion key: ");
		key = getUserInput();
		
		if (!compareKey(serviceName, hashString(key)))
		{
			System.out.println("\nInvalid key given. Returning to main menu.");
			return;
		}
		
		System.out.println("");
		System.out.println("Valid key given. Now decrypting account credentials.");
		String username = decrypt(getUsername(serviceName), key);
		String password = decrypt(getPassword(serviceName), key);
		
		System.out.print("> Credentials decrypted. Press Enter to show.");
		scanner.nextLine();
		
		System.out.println("A dialog box with your credentials should now be showing. If not, "
				+ "contact the developer regarding this issue.");
		
		JTextArea textArea = new JTextArea("Username:  " + username + "\nPassword:  " + password, 2, 5);
		textArea.setLineWrap(false);
		textArea.setEditable(false);
		
		JOptionPane.showMessageDialog(null, textArea, 
				"Credentials for " + serviceName, JOptionPane.PLAIN_MESSAGE);		
	}
	
	private void deleteServiceEntry(String[] input)
	{
		String serviceName = getServiceName(input);
		if (serviceName.equals(""))
		{
			System.out.println("No service name provided. Please include the service name when entering a option.");
			return;
		}
		
		if (!isService(serviceName))
		{
			System.out.println("The service you've enter does not have a stored password. "
					+ "(Service name is case-sensitive)");
			return;
		}
		
		boolean validResponse = false;
		boolean delete = false;
		String response = "";
		
		do
		{
			System.out.print("Are you sure you wish to delete " + serviceName + " from the manager? (Y/N): ");
			response = getUserInput();
			
			if (response.equalsIgnoreCase("y") || response.equalsIgnoreCase("n"))
			{
				validResponse = true;
				delete = response.equalsIgnoreCase("y");
			}
			else
			{
				System.out.print("- Notice: Invalid response. \nPlease respond with Y or N.");
			}
		} while (!validResponse);
		
		if (delete)
		{
			removeService(serviceName);
			System.out.println(serviceName + " has been deleted.");
		}
		else
		{
			System.out.println("Service not deleted.");
		}
	}
	
	
	/*
	 *  Utils
	 */
	private void printErrorMessage(Exception e)
	{
		System.out.println("[ERROR] An error has occured. Please contact the developer about how you came upon this error.");
		if (showDebug)
			e.printStackTrace();
	}
	
	private void pauseTillEnter()
	{
		System.out.print(">> Press Enter to continue >>");
		scanner.nextLine();
	}
	
	private boolean validInput(String input)
	{
		return input.matches("^[a-zA-Z0-9!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?]*$");
	}
	
	private String getUserInput()
	{
		String input = "";
		
		do
		{
			input = scanner.nextLine().stripTrailing().stripLeading();
		} while (input.equals(""));
		
		return input;
	}
	
	private String getServiceName(String[] input)
	{	
		if (input.length <= 1)
			return "";
		
		StringBuilder sb = new StringBuilder();
		for (int i = 1; i < input.length; i++)
			sb.append(input[i] + " ");
		sb.deleteCharAt(sb.length() - 1);
		
		return sb.toString();
	}
	
	private String hashString(String pw)
	{
		/*
		 * Following code is based on the following linked guide:
		 * https://www.tutorialspoint.com/java_cryptography/java_cryptography_message_digest.htm
		 * 
		 * Modifications made where needed.
		 */
		
		try
		{
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] hashedPw = md.digest(pw.getBytes(StandardCharsets.UTF_8));
			
			StringBuffer hexedHashedPW = new StringBuffer();
			for (int i = 0; i < hashedPw.length; i++)
				hexedHashedPW.append(String.format("%02x", hashedPw[i]));
			
			return hexedHashedPW.toString();
			
		} catch (Exception e) { printErrorMessage(e); }
		
		return pw; // No such algorithm exist provided return the original password. Odds of it being that is very low.
	}
	
	/*
	 * The code for encrypt and decrypt are based on the following linked guide:
	 * https://www.tutorialspoint.com/symmetric-encryption-cryptography-in-java
	 * 
	 * Modifications made where needed.
	 */
	
	private String encrypt(String msg, String key)
	{
		String result = msg;
		try 
		{
			// Key get hashed to match required bitsize
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] hashedKey = md.digest(key.getBytes());
			SecretKey sKey = new SecretKeySpec(hashedKey, "AES");
			
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, sKey);
			
			byte[] encryptedBytes = cipher.doFinal(msg.getBytes(StandardCharsets.UTF_8));
			result = Base64.getEncoder().encodeToString(encryptedBytes);
			
		} catch (Exception e) { printErrorMessage(e); }
		
		return result;
	}
	
	private String decrypt(String msg, String key)
	{
		String result = msg;
		try 
		{
			// Key get hashed to match required bitsize
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] hashedKey = md.digest(key.getBytes());
			SecretKey sKey = new SecretKeySpec(hashedKey, "AES");
			
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, sKey);
			
			byte[] decryptedMessage = Base64.getDecoder().decode(msg);
			byte[] decryptedBytes = cipher.doFinal(decryptedMessage);
			
			result = new String(decryptedBytes, StandardCharsets.UTF_8);
			
		} catch (Exception e) { printErrorMessage(e); }
		
		return result;
	}
	
	
	
	/* 
	 *  Database
	 */	
	private boolean dbConnect()
	{
		if (this.con != null) dbDisconnect();
		try 
		{
			this.con = DriverManager.getConnection(ADDRESS);
			if (showDebug)
				System.out.println("[Info] Database connection opened.");
		} 
		catch (SQLException e) 
		{ 
			printErrorMessage(e);
			return false;
		}
		
		return true;
	}
	
	private void dbDisconnect()
	{
		try
		{
			if (this.con != null && !this.con.isClosed())
			{
				this.con.close();
				if (showDebug)
					System.out.println("[Info] Database connection closed.");
				this.con = null;
			}
				
		} catch (SQLException e) { printErrorMessage(e); }
	}
	
	private ResultSet dbQuery(PreparedStatement st)
	{
		ResultSet rs = null;
		
		try
		{
			rs = st.executeQuery();
		} catch (SQLException e) { printErrorMessage(e); }
		
		return rs;
	}
	
	private void dbUpdate(PreparedStatement st)
	{
		try
		{
			st.executeUpdate();
			st.close();
		} catch (SQLException e) { printErrorMessage(e); }
	}
	
	
	
	/*
	 *  SQL Handling
	 */
	private void addNewUser(String username, String password, String tableID)
	{
		dbConnect();
		
		try
		{
			PreparedStatement st1 = this.con.prepareStatement(
					"INSERT INTO accounts (user, password, tableID) VALUES (?, ?, ?)");
			st1.setString(1, username.toLowerCase());
			st1.setString(2, password);
			st1.setString(3, tableID);
			
			dbUpdate(st1);
			
			PreparedStatement st2 = this.con.prepareStatement(
					"CREATE TABLE '" + tableID + "' (service TEXT PRIMARY KEY, username TEXT, password TEXT, decryptKey TEXT);"); 
			// SQL Injection is not a concern as tableID is not and will never be a user input.
			
			dbUpdate(st2);			
		} catch (SQLException e) { printErrorMessage(e); } 
		
		dbDisconnect();
	}
	
	private boolean userExist(String username)
	{
		dbConnect();
		
		boolean userExists = false;
		
		try
		{
			PreparedStatement st = con.prepareStatement(
					"SELECT * FROM accounts WHERE user=?");
			st.setString(1, username.toLowerCase()); // Usernames are stored lowercase
			
			ResultSet rs = dbQuery(st);
			
			if (rs.next())
				userExists = rs.getString("user") != null;
			
		} catch (SQLException e) { printErrorMessage(e); } 
		
		dbDisconnect();
		
		return userExists;
	}
	
	private boolean passwordMatch(String username, String password)
	{
		dbConnect();
		
		boolean userExists = false;
		
		try
		{
			PreparedStatement st = con.prepareStatement(
					"SELECT * FROM accounts WHERE user=? AND password=?");
			st.setString(1, username.toLowerCase()); // Usernames are stored lowercase
			st.setString(2, password);
			
			ResultSet rs = dbQuery(st);
			
			if (rs.next())
				userExists = rs.getString("user") != null;
			
		} catch (SQLException e) { printErrorMessage(e); } 
		
		dbDisconnect();
		
		return userExists;
	}
	
	private boolean tableIDExist(String tableID)
	{
		dbConnect();
		boolean tableIDExists = false;
		
		try
		{
			PreparedStatement st = con.prepareStatement(
					"SELECT * FROM accounts WHERE tableID=?");
			st.setString(1, tableID);
			
			ResultSet rs = dbQuery(st);
			
			if (rs.next())
				tableIDExists = rs.getString("tableID") != null;
			
		} catch (SQLException e) { printErrorMessage(e); } 
			
		dbDisconnect();
		
		return tableIDExists;
	}
	
	private String getUserTableID(String username)
	{
		dbConnect();
		String userTableID = "";
		
		try
		{
			PreparedStatement st = con.prepareStatement(
					"SELECT * FROM accounts WHERE user=?");
			st.setString(1, username);
			
			ResultSet rs = dbQuery(st);
			
			if (rs.next())
				userTableID = rs.getString("tableID");
		} catch (SQLException e) { printErrorMessage(e); }
		
		dbDisconnect();
		
		return userTableID;
	}
	
	private List<String> getServices()
	{
		List<String> theList = new ArrayList<String>();
		
		dbConnect();
		
		try
		{
			PreparedStatement st = this.con.prepareStatement(
					"SELECT service FROM '" + userTableID + "';");
			
			ResultSet rs = dbQuery(st);
			while(rs.next())
				theList.add(rs.getString("service"));
		} catch (SQLException e) { printErrorMessage(e); }
		
		dbDisconnect();
		
		return theList;
	}
	
	private void addNewService(String service, String username, String password, String key)
	{
		dbConnect();
		
		try
		{
			PreparedStatement st = this.con.prepareStatement(
					"INSERT INTO '" + userTableID + "' (service, username, password, decryptKey) VALUES (?, ?, ?, ?)");
			st.setString(1, service);
			st.setString(2, username);
			st.setString(3, password);
			st.setString(4, key);
			
			dbUpdate(st);
		} catch (SQLException e) { printErrorMessage(e); }
		
		dbDisconnect();
	}
	
	private void removeService(String service)
	{
		dbConnect();
		
		try
		{
			PreparedStatement st = this.con.prepareStatement(
					"DELETE FROM '" + userTableID + "' WHERE service=?;");
			st.setString(1, service);
			
			dbUpdate(st);
		} catch (SQLException e) { printErrorMessage(e); }
		
		dbDisconnect();
	}
	
	private boolean isService(String service)
	{
		dbConnect();
		boolean result = false;
		
		try
		{
			PreparedStatement st = this.con.prepareStatement(
					"SELECT * FROM '" + userTableID + "' WHERE service=?;");
			st.setString(1, service);
			
			ResultSet rs = dbQuery(st);
			if (rs.next())
				result = true;
		} catch (SQLException e) { printErrorMessage(e); }
		
		dbDisconnect();
		
		return result;
	}
	
	private boolean compareKey(String service, String key)
	{
		dbConnect();
		String dbKey = "";
		
		try
		{
			PreparedStatement st = this.con.prepareStatement(
					"SELECT * FROM '" + userTableID + "' WHERE service=?;");
			st.setString(1, service);
			
			ResultSet rs = dbQuery(st);
			if (rs.next())
				dbKey = rs.getString("decryptKey");
		} catch (SQLException e) { printErrorMessage(e); }
		
		dbDisconnect();
		
		return (dbKey.equals(key));
	}
	
	private String getPassword(String service)
	{
		dbConnect();
		String password = "";
		
		try
		{
			PreparedStatement st = this.con.prepareStatement(
					"SELECT * FROM '" + userTableID + "' WHERE service=?;");
			st.setString(1, service);
			
			ResultSet rs = dbQuery(st);
			if (rs.next())
				password = rs.getString("password");
		} catch (SQLException e) { printErrorMessage(e); }
		
		dbDisconnect();
		
		return password;
	}
	
	private String getUsername(String service)
	{
		dbConnect();
		String username = "";
		
		try
		{
			PreparedStatement st = this.con.prepareStatement(
					"SELECT * FROM '" + userTableID + "' WHERE service=?;");
			st.setString(1, service);
			
			ResultSet rs = dbQuery(st);
			if (rs.next())
				username = rs.getString("username");
		} catch (SQLException e) { printErrorMessage(e); }
		
		dbDisconnect();
		
		return username;
	}
}
