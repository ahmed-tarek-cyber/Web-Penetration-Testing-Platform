Database Migrations — SphinxEye / WebScanner
============================================

Database: ScanlyDB (SQL Server)
Connection string (in Program.cs):
  Server=.;Database=ScanlyDB;Trusted_Connection=True;TrustServerCertificate=True;

Migrations live in: WebScanner/Migrations/


Included migrations (in order)
----------------------------

1. 20251211170227_InitialCreate
   - Base tables (users, scan reports, vulnerabilities, etc.)

2. 20251215191409_UpdateUserTable
   - User table updates

3. 20251215220422_AddUserIdToReport
   - Links scan reports to users

4. 20260502165832_AddSourceCodeReviewReportToDb
   - SourceCodeReviewReports table for uploaded file reviews

5. 20260607220055_AddChatSystem
   - ChatSessions and ChatMessages
   - Links chat to scan reports and source code review reports


Apply migrations (recommended)
------------------------------

1. Install the EF tool (once):
     dotnet tool install --global dotnet-ef

2. From the WebScanner folder:
     dotnet ef database update

That creates or updates ScanlyDB to match the current schema.


Fresh database from scratch
---------------------------

Option A — EF (use this in normal development):
  cd WebScanner
  dotnet ef database update

Option B — SQL script only:
  Run sql_init/init_schema.sql in SSMS against your SQL Server instance.
  This is a manual fallback. It may not include every column from the latest
  EF migrations. Prefer dotnet ef database update when you can.


Add a new migration (when you change models)
--------------------------------------------

  cd WebScanner
  dotnet ef migrations add YourMigrationName
  dotnet ef database update


Notes
-----

- The old placeholder migration file mentioned in earlier docs is gone.
  Real C# migration files are under WebScanner/Migrations/.
- Source code review also writes JSON/HTML files under the app output folder
  (SourceCodeReviewReports/{userId}/). The database holds the report metadata
  and findings JSON.
- If dotnet ef fails, check that SQL Server is running and the connection
  string in Program.cs matches your machine.
