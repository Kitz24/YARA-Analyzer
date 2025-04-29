# YARA File Analyzer

A minimal file analyzer that uses YARA rules to scan files for known patterns and indicators, complete with a VirusTotal API Integration.

## 🔧 Setup

Clone the repository and install dependencies:

    git clone https://github.com/Kitz24/YARA-Analyzer.git
    cd YARA-Analyzer
    pip install -r requirements.txt

## 🚀 Usage

Run the analyzer with the target filename as an argument:

    python main.py <filename>

Replace `<filename>` with the path to the file you want to scan.

## 🛠️ YARA Rules

YARA rules are located at:

    /resources/tesla.yar

You can edit this file to modify or add your own rules.

## 📄 Description

This tool performs lightweight, rule-based file scanning using the YARA pattern-matching engine. Useful for malware detection, threat hunting, and signature-based analysis.

