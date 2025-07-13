-- إنشاء قاعدة البيانات
CREATE DATABASE CyberThreatIntelDB;
GO

-- استخدام قاعدة البيانات
USE CyberThreatIntelDB;
GO

-- جدول التصنيفات (Categories)
CREATE TABLE Categories (
    CategoryID INT PRIMARY KEY IDENTITY(1,1),
    CategoryName VARCHAR(50) NOT NULL
);
GO

-- جدول الدول (Countries)
CREATE TABLE Countries (
    CountryID INT PRIMARY KEY IDENTITY(1,1),
    CountryName VARCHAR(100) NOT NULL
);
GO

-- جدول مصادر البيانات (Sources)
CREATE TABLE Sources (
    SourceID INT PRIMARY KEY IDENTITY(1,1),
    SourceName VARCHAR(100) NOT NULL,
    SourceType VARCHAR(50),
    SourceURL VARCHAR(255)
);
GO

-- جدول التهديدات (Threats)
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
