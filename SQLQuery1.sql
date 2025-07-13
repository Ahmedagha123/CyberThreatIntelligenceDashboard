-- Create DataBase
CREATE DATABASE CyberThreatIntelDB;
GO

-- Use DataBase
USE CyberThreatIntelDB;
GO

-- (Categories)
CREATE TABLE Categories (
    CategoryID INT PRIMARY KEY IDENTITY(1,1),
    CategoryName VARCHAR(50) NOT NULL
);
GO

--  (Countries)
CREATE TABLE Countries (
    CountryID INT PRIMARY KEY IDENTITY(1,1),
    CountryName VARCHAR(100) NOT NULL
);
GO

--  (Sources)
CREATE TABLE Sources (
    SourceID INT PRIMARY KEY IDENTITY(1,1),
    SourceName VARCHAR(100) NOT NULL,
    SourceType VARCHAR(50),
    SourceURL VARCHAR(255)
);
GO

--  (Threats)
CREATE TABLE Threats (
    ThreatID INT PRIMARY KEY IDENTITY(1,1),
    ThreatName VARCHAR(100) NOT NULL,
    CategoryID INT FOREIGN KEY REFERENCES Categories(CategoryID),
    Severity VARCHAR(20),
    SourceIP VARCHAR(50),
    CountryID INT FOREIGN KEY REFERENCES Countries(CountryID),
    ReportDate DATE,
    Description TEXT,
    Status VARCHAR(20),
    SourceID INT FOREIGN KEY REFERENCES Sources(SourceID)
);
GO
