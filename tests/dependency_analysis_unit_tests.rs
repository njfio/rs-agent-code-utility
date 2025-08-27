//! Comprehensive unit tests for dependency analysis functionality
//! 
//! These tests verify the accuracy and reliability of dependency detection
//! and analysis across different package managers and programming languages.

use rust_tree_sitter::{DependencyAnalyzer, AnalysisResult, FileInfo, Result};
use std::path::PathBuf;
use std::collections::HashMap;
use tempfile::TempDir;
use std::fs;

fn create_analysis_result_with_fs(specs: Vec<(&str, &str, &str)>) -> (TempDir, AnalysisResult) {
    let temp_dir = TempDir::new().expect("failed to create temp project dir");
    let root = temp_dir.path();

    let mut files: Vec<FileInfo> = Vec::new();
    for (rel, content, language) in specs {
        let p = root.join(rel);
        if let Some(parent) = p.parent() { fs::create_dir_all(parent).unwrap(); }
        fs::write(&p, content).expect("failed to write test file");

        files.push(FileInfo {
            path: PathBuf::from(rel),
            language: language.to_string(),
            lines: content.lines().count(),
            symbols: vec![],
            parsed_successfully: true,
            parse_errors: vec![],
            security_vulnerabilities: vec![],
            size: content.len(),
        });
    }

    let total_files = files.len();
    let total_lines = files.iter().map(|f| f.lines).sum();

    let ar = AnalysisResult {
        root_path: root.to_path_buf(),
        total_files,
        parsed_files: total_files,
        error_files: 0,
        total_lines,
        languages: HashMap::new(),
        files,
        config: rust_tree_sitter::AnalysisConfig::default(),
    };

    (temp_dir, ar)
}

#[test]
fn test_dependency_analyzer_creation() {
    let _analyzer = DependencyAnalyzer::new();
    // Analyzer should be created successfully
}

#[test]
fn test_cargo_toml_dependency_detection() -> Result<()> {
    let analyzer = DependencyAnalyzer::new();
    
    let cargo_toml_content = r#"
[package]
name = "test-project"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
tokio = { version = "1.0", features = ["full"] }
anyhow = "1.0"
clap = { version = "4.0", optional = true }

[dev-dependencies]
tempfile = "3.0"
criterion = "0.5"

[build-dependencies]
cc = "1.0"
    "#;
    
    let (_tmp, analysis_result) = create_analysis_result_with_fs(vec![
        ("Cargo.toml", cargo_toml_content, "toml")
    ]);
    
    let dependency_result = analyzer.analyze(&analysis_result)?;
    
    // Should detect Cargo dependencies
    assert!(!dependency_result.dependencies.is_empty());
    
    let serde_found = dependency_result.dependencies.iter()
        .any(|d| d.name == "serde");
    let tokio_found = dependency_result.dependencies.iter()
        .any(|d| d.name == "tokio");
    let anyhow_found = dependency_result.dependencies.iter()
        .any(|d| d.name == "anyhow");
    
    assert!(serde_found, "serde dependency should be detected");
    assert!(tokio_found, "tokio dependency should be detected");
    assert!(anyhow_found, "anyhow dependency should be detected");
    
    Ok(())
}

#[test]
fn test_package_json_dependency_detection() -> Result<()> {
    let analyzer = DependencyAnalyzer::new();
    
    let package_json_content = r#"
{
  "name": "test-project",
  "version": "1.0.0",
  "description": "Test project",
  "main": "index.js",
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "^4.17.21",
    "axios": "^1.0.0"
  },
  "devDependencies": {
    "jest": "^29.0.0",
    "eslint": "^8.0.0",
    "@types/node": "^18.0.0"
  },
  "peerDependencies": {
    "react": "^18.0.0"
  }
}
    "#;
    
    let (_tmp, analysis_result) = create_analysis_result_with_fs(vec![
        ("package.json", package_json_content, "json")
    ]);
    
    let dependency_result = analyzer.analyze(&analysis_result)?;
    
    // Should detect npm dependencies
    assert!(!dependency_result.dependencies.is_empty());
    
    let express_found = dependency_result.dependencies.iter()
        .any(|d| d.name == "express");
    let lodash_found = dependency_result.dependencies.iter()
        .any(|d| d.name == "lodash");
    let jest_found = dependency_result.dependencies.iter()
        .any(|d| d.name == "jest");
    
    assert!(express_found, "express dependency should be detected");
    assert!(lodash_found, "lodash dependency should be detected");
    assert!(jest_found, "jest dev dependency should be detected");
    
    Ok(())
}

#[test]
fn test_malformed_package_json_reports_error() {
    let analyzer = DependencyAnalyzer::new();

    let bad_json = "{ \n  \"dependencies\": { \n    \"express\": ^4.18.0 \n  } \n}"; // missing quotes around version

    let (_tmp, analysis_result) = create_analysis_result_with_fs(vec![
        ("package.json", bad_json, "json")
    ]);

    let res = analyzer.analyze(&analysis_result);
    assert!(res.is_err());
    let msg = res.err().unwrap().to_string();
    assert!(msg.contains("Failed to parse package.json"));
}

#[test]
fn test_malformed_cargo_toml_reports_error() {
    let analyzer = DependencyAnalyzer::new();

    let bad_toml = "[dependencies]\nserde = { version = 1.0 }"; // version must be string

    let (_tmp, analysis_result) = create_analysis_result_with_fs(vec![
        ("Cargo.toml", bad_toml, "toml")
    ]);

    let res = analyzer.analyze(&analysis_result);
    assert!(res.is_err());
    let msg = res.err().unwrap().to_string();
    assert!(msg.contains("Cargo.toml") || msg.contains("Invalid version type in Cargo.toml"));
}

#[test]
fn test_python_requirements_detection() -> Result<()> {
    let analyzer = DependencyAnalyzer::new();
    
    let requirements_content = r#"
# Core dependencies
requests==2.28.0
numpy>=1.21.0
pandas==1.5.0
flask>=2.0.0,<3.0.0

# Development dependencies
pytest==7.1.0
black==22.0.0
mypy>=0.950

# Optional dependencies
matplotlib==3.5.0  # For plotting
scikit-learn>=1.1.0  # Machine learning
    "#;
    
    let (_tmp, analysis_result) = create_analysis_result_with_fs(vec![
        ("requirements.txt", requirements_content, "text")
    ]);
    
    let dependency_result = analyzer.analyze(&analysis_result)?;
    
    // Should detect Python dependencies
    assert!(!dependency_result.dependencies.is_empty());
    
    let requests_found = dependency_result.dependencies.iter()
        .any(|d| d.name == "requests");
    let numpy_found = dependency_result.dependencies.iter()
        .any(|d| d.name == "numpy");
    let pandas_found = dependency_result.dependencies.iter()
        .any(|d| d.name == "pandas");
    
    assert!(requests_found, "requests dependency should be detected");
    assert!(numpy_found, "numpy dependency should be detected");
    assert!(pandas_found, "pandas dependency should be detected");
    
    Ok(())
}

#[test]
fn test_go_mod_dependency_detection() -> Result<()> {
    let analyzer = DependencyAnalyzer::new();
    
    let go_mod_content = r#"
module github.com/example/test-project

go 1.19

require (
    github.com/gin-gonic/gin v1.9.0
    github.com/stretchr/testify v1.8.0
    golang.org/x/crypto v0.5.0
    gorm.io/gorm v1.24.0
)

require (
    github.com/bytedance/sonic v1.8.0 // indirect
    github.com/chenzhuoyu/base64x v0.0.0-20221115062448-fe3a3abad311 // indirect
    github.com/gin-contrib/sse v0.1.0 // indirect
)
    "#;
    
    let (_tmp, analysis_result) = create_analysis_result_with_fs(vec![
        ("go.mod", go_mod_content, "go")
    ]);
    
    let dependency_result = analyzer.analyze(&analysis_result)?;
    
    // Should detect Go dependencies
    assert!(!dependency_result.dependencies.is_empty());
    
    let gin_found = dependency_result.dependencies.iter()
        .any(|d| d.name.contains("gin-gonic/gin"));
    let testify_found = dependency_result.dependencies.iter()
        .any(|d| d.name.contains("stretchr/testify"));
    let crypto_found = dependency_result.dependencies.iter()
        .any(|d| d.name.contains("golang.org/x/crypto"));
    
    assert!(gin_found, "gin dependency should be detected");
    assert!(testify_found, "testify dependency should be detected");
    assert!(crypto_found, "crypto dependency should be detected");
    
    Ok(())
}

#[test]
fn test_rust_source_imports_detection() -> Result<()> {
    let analyzer = DependencyAnalyzer::new();
    
    let rust_source = r#"
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::{Serialize, Deserialize};
use tokio::runtime::Runtime;
use anyhow::{Result, Context};
use clap::{Parser, Subcommand};

extern crate log;
extern crate env_logger;

mod utils;
mod config;

use crate::utils::helper_function;
use crate::config::AppConfig;

fn main() {
    println!("Hello, world!");
}
    "#;
    
    let (_tmp, analysis_result) = create_analysis_result_with_fs(vec![
        ("main.rs", rust_source, "Rust")
    ]);
    
    let dependency_result = analyzer.analyze(&analysis_result)?;
    
    // Should detect imports from source code
    assert!(!dependency_result.dependencies.is_empty());
    
    let serde_import = dependency_result.dependencies.iter()
        .any(|d| d.name == "serde");
    let tokio_import = dependency_result.dependencies.iter()
        .any(|d| d.name == "tokio");
    let anyhow_import = dependency_result.dependencies.iter()
        .any(|d| d.name == "anyhow");
    
    assert!(serde_import, "serde import should be detected");
    assert!(tokio_import, "tokio import should be detected");
    assert!(anyhow_import, "anyhow import should be detected");
    
    Ok(())
}

#[test]
fn test_javascript_imports_detection() -> Result<()> {
    let analyzer = DependencyAnalyzer::new();
    
    let js_source = r#"
import express from 'express';
import { Router } from 'express';
import * as lodash from 'lodash';
import axios from 'axios';

const fs = require('fs');
const path = require('path');
const { promisify } = require('util');

// Dynamic imports
const dynamicModule = await import('./dynamic-module.js');

// Local imports
import { helper } from './utils/helper.js';
import config from '../config/app.config.js';

export default function app() {
    const router = Router();
    return router;
}
    "#;
    
    let (_tmp, analysis_result) = create_analysis_result_with_fs(vec![
        ("app.js", js_source, "JavaScript")
    ]);
    
    let dependency_result = analyzer.analyze(&analysis_result)?;
    
    // Should detect JavaScript imports
    assert!(!dependency_result.dependencies.is_empty());
    
    let express_import = dependency_result.dependencies.iter()
        .any(|d| d.name == "express");
    let lodash_import = dependency_result.dependencies.iter()
        .any(|d| d.name == "lodash");
    let axios_import = dependency_result.dependencies.iter()
        .any(|d| d.name == "axios");
    
    assert!(express_import, "express import should be detected");
    assert!(lodash_import, "lodash import should be detected");
    assert!(axios_import, "axios import should be detected");
    
    Ok(())
}

#[test]
fn test_python_imports_detection() -> Result<()> {
    let analyzer = DependencyAnalyzer::new();
    
    let python_source = r#"
import os
import sys
from pathlib import Path

import requests
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify
from sklearn.model_selection import train_test_split

# Relative imports
from .utils import helper_function
from ..config import settings

# Conditional imports
try:
    import matplotlib.pyplot as plt
except ImportError:
    plt = None

def main():
    app = Flask(__name__)
    return app
    "#;
    
    let (_tmp, analysis_result) = create_analysis_result_with_fs(vec![
        ("app.py", python_source, "Python")
    ]);
    
    let dependency_result = analyzer.analyze(&analysis_result)?;
    
    // Should detect Python imports
    assert!(!dependency_result.dependencies.is_empty());
    
    let requests_import = dependency_result.dependencies.iter()
        .any(|d| d.name == "requests");
    let numpy_import = dependency_result.dependencies.iter()
        .any(|d| d.name == "numpy");
    let flask_import = dependency_result.dependencies.iter()
        .any(|d| d.name == "flask");
    
    assert!(requests_import, "requests import should be detected");
    assert!(numpy_import, "numpy import should be detected");
    assert!(flask_import, "flask import should be detected");
    
    Ok(())
}

#[test]
fn test_mixed_project_dependency_analysis() -> Result<()> {
    let analyzer = DependencyAnalyzer::new();
    
    let cargo_toml = r#"
[dependencies]
serde = "1.0"
tokio = "1.0"
    "#;
    
    let package_json = r#"
{
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "^4.17.21"
  }
}
    "#;
    
    let rust_code = r#"
use serde::Serialize;
use std::collections::HashMap;
    "#;
    
    let js_code = r#"
import express from 'express';
import lodash from 'lodash';
    "#;
    
    let (_tmp, analysis_result) = create_analysis_result_with_fs(vec![
        ("Cargo.toml", cargo_toml, "toml"),
        ("package.json", package_json, "json"),
        ("src/main.rs", rust_code, "Rust"),
        ("src/app.js", js_code, "JavaScript"),
    ]);
    let dependency_result = analyzer.analyze(&analysis_result)?;
    
    // Should detect dependencies from both Rust and JavaScript
    assert!(!dependency_result.dependencies.is_empty());
    
    let has_rust_deps = dependency_result.dependencies.iter()
        .any(|d| d.name == "serde" || d.name == "tokio");
    let has_js_deps = dependency_result.dependencies.iter()
        .any(|d| d.name == "express" || d.name == "lodash");
    
    assert!(has_rust_deps, "Should detect Rust dependencies");
    assert!(has_js_deps, "Should detect JavaScript dependencies");
    
    Ok(())
}

#[test]
fn test_dependency_version_parsing() -> Result<()> {
    let analyzer = DependencyAnalyzer::new();
    
    let cargo_toml_content = r#"
[dependencies]
serde = "1.0.136"
tokio = { version = "1.21.0", features = ["full"] }
anyhow = ">=1.0.0"
clap = "~4.0.0"
    "#;
    
    let (_tmp, analysis_result) = create_analysis_result_with_fs(vec![
        ("Cargo.toml", cargo_toml_content, "toml")
    ]);
    
    let dependency_result = analyzer.analyze(&analysis_result)?;
    
    // Should parse version information
    let serde_dep = dependency_result.dependencies.iter()
        .find(|d| d.name == "serde");
    
    if let Some(dep) = serde_dep {
        assert!(!dep.version.is_empty(), "Version should be parsed");
    }
    
    Ok(())
}

#[test]
fn test_empty_project_analysis() -> Result<()> {
    let analyzer = DependencyAnalyzer::new();
    
    let (_tmp, analysis_result) = create_analysis_result_with_fs(vec![
        ("empty.rs", "", "Rust")
    ]);
    
    let dependency_result = analyzer.analyze(&analysis_result)?;
    
    // Empty project should have no dependencies
    assert_eq!(dependency_result.dependencies.len(), 0);
    
    Ok(())
}
