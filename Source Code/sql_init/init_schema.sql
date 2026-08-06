-- init_schema.sql
-- Generated: 2025-10-11T22:53:17.135956Z
-- Creates tables for WebScanner project: Users, Reports, Vulnerabilities
-- Adjust types and constraints as needed for your environment.
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

IF DB_ID(N'WebScannerDB') IS NULL
BEGIN
    CREATE DATABASE [WebScannerDB];
END
GO

USE [WebScannerDB];
GO

-- Users table
IF OBJECT_ID(N'dbo.Users', N'U') IS NULL
BEGIN
CREATE TABLE [dbo].[Users] (
    [Id] INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
    [Name] NVARCHAR(200) NOT NULL,
    [Email] NVARCHAR(256) NOT NULL,
    [PasswordHash] NVARCHAR(512) NOT NULL,
    [CreatedAt] DATETIME2 NOT NULL DEFAULT (SYSUTCDATETIME())
);
CREATE UNIQUE INDEX IX_Users_Email ON dbo.Users(Email);
END
GO

-- Reports table (ScanReport)
IF OBJECT_ID(N'dbo.Reports', N'U') IS NULL
BEGIN
CREATE TABLE [dbo].[Reports] (
    [Id] NVARCHAR(450) NOT NULL PRIMARY KEY,
    [Url] NVARCHAR(MAX) NULL,
    [AiSummary] NVARCHAR(MAX) NULL
);
END
GO

-- Vulnerabilities table
IF OBJECT_ID(N'dbo.Vulnerabilities', N'U') IS NULL
BEGIN
CREATE TABLE [dbo].[Vulnerabilities] (
    [Id] INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
    [Name] NVARCHAR(MAX) NOT NULL,
    [Severity] NVARCHAR(MAX) NOT NULL,
    [Description] NVARCHAR(MAX) NOT NULL,
    [Color] NVARCHAR(MAX) NULL,
    [AccentColor] NVARCHAR(MAX) NULL,
    [ScanReportId] NVARCHAR(450) NOT NULL
);
ALTER TABLE dbo.Vulnerabilities
    ADD CONSTRAINT FK_Vulnerabilities_Reports_ScanReportId FOREIGN KEY (ScanReportId) REFERENCES dbo.Reports(Id) ON DELETE CASCADE;
END
GO

-- Example: insert test user (remove in production)
IF NOT EXISTS (SELECT 1 FROM dbo.Users WHERE Email = 'test@example.com')
BEGIN
    INSERT INTO dbo.Users (Name, Email, PasswordHash) VALUES ('Test User', 'test@example.com', 'FAKE_HASH_FOR_TEST');
END
GO