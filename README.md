# Forensic-Scripts_Collectors-and-Reviewers
HISTORY

This project has been about thirty years in the making.  While working forensics for the government in the late 90's to the early 00's I was writing my own scripts in Perl for specific needs whenever there was not a current toolor to fill a specific need, such as hashing and hash matching.  Over the years these tools have been written in Perl, Perl/Tk, VB.NET, Python, and now finally Python/Qt.  The final versions were availble mainly due to ChatGPT.  I had begon working to convert the VB version to Pyton with a GUI interface about two years ago.  After adding too much, the Python/Tk interface required conversion to a QT version.  While trying to complete the conversion along came ChatGPT which helped with the final conversion

The final versions fill a need I have for a quick review and triage of images for a variety of reasons, including reviewing users actions, access to documents, use of the Internet, review of email, email logs, and other information.

USES

The entire repository is written in Python and should be available to use whereever Python is installed so long as the requirements are install.

Download the entire repository; run the following as admin.

After downloading navigate to the root directory and run the following command to ensure all requirments are installed:

  pip install -r requirments.txt

After all requirements have been installed, the program can be started with the following being run as admin:

  run_forensics.bat

If this is the first time running the program, there will be a folder created and installed at the same level called "Forensics Collector Global Settings".  This folder contains some of the information need to run the progam, but it also serves as a repository for any additional scripts, tools, settings, etc.  The folder makes the tools expandable and customizable.  The folder contains the following subfolders:

    Python Scripts
    Registry Libraries
    Bookmark Categories
    Exports
    Icons
    Logs
    Report Templates
    SQL Queries
    Timeline Configurations

Not all of the folders are populated with any files, but they were useful during prior versions and I choose to keep them.  The files in the folders will be read when the program is opened and any cutomization will been incorporated into the program.

For example: 
  the "Python Scripts" will be accessible in the "Scripts" tab,
  the "Registry Libraries" will be accessible in "Registry" tab,



    
