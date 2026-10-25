# Project Instructions

## Team Formation
- Projects will be completed in **teams of 4 students**.  
- Each team must select **one project** from the provided list.  
- Carefully review the project description and deliverables before starting.  

---

## Submission Guidelines
- **Deadline:** Friday, May 5 at 11:59 PM.  
- **Submission Platform:** GitHub Classroom.  
- Your project code must be submitted along with **Docker files** so the program can be run as a **Docker container**.  

---

## Grading & Presentation
- Project is worth 20% of total course grade.
- After submission, additional instructions will be shared to schedule a **20-minute grading session** with the Teaching Assistants (TAs).  
- **Presentation Requirements:**  
  - Maximum duration: **20 minutes**.  
  - You may use a **slideshow** to support your presentation.  
  - You must **demonstrate your program live** on your laptop.  
- **TA Evaluation:**  
  - TAs will review your GitHub repository during the session.  
  - You will be asked to run your program, provide input scenarios, and test edge cases.  
  - TAs will ask questions to assess your team’s understanding of the project.  

---

## Key Reminders
- Ensure your **Docker setup works correctly** so the program can be easily run as soon as you start your session. Technical issues with your Docker will deduct from the time your presentation time and will affect your grading.  
- Keep your presentation concise and focused on demonstrating functionality.  
- Be prepared to explain your design decisions, handle test cases, and answer technical questions.  

## 📢 Important Note on Using LLMs

You are welcome to use **Large Language Models (LLMs)** to assist with your project.  
However, you must follow these guidelines:

- **Validate all code**: Ensure that any code generated or suggested by an LLM is correct, functional, and fully understood by your team.  
- **Take ownership of learning**: Use LLMs as a tool to support your work, not as a substitute for your own understanding.  
- **Do not share your work with peers**: Sharing code between teams undermines the learning process. Each team must complete the project independently. Also, TAs have full access to your GitHub repositories and will be able to detect cases of plagiarism.  

Remember: copying or sharing code doesn’t just risk penalties—it **steals your peers’ opportunity to learn** and weakens your own mastery of the material. **I trust you** to reasonably use LLMs and submit your own work. 

--- 

# Project 2: SBOM Generator

## TAs: Salma Salem and Omar Usama

---

## Overview
Students will build a **Software Bill of Materials (SBOM) generator** that scans project directories, identifies dependencies across multiple ecosystems, resolves transitive dependency trees, and produces SBOM documents in **[SPDX](https://spdx.dev/)** or **[CycloneDX](https://cyclonedx.org/)** formats or both.  

The tool will also cross-reference discovered packages against CVE databases (NVD or OSV) to generate vulnerability reports alongside the SBOM.  

This project is directly relevant to **[US Executive Order 14028](https://www.federalregister.gov/documents/2021/05/17/2021-10460/improving-the-nations-cybersecurity)** on improving national cybersecurity, which mandates SBOM production for all software sold to the federal government. Mastering SBOM generation is therefore a **marketable real-world skill**.

---

## What is an SBOM?
A SBOM is a machine-readable inventory of all components in a piece of software.  
It lists libraries, frameworks, modules, and transitive dependencies — essentially an “ingredient list” for software.  
SBOMs are critical for **security, compliance, and transparency** in the software supply chain.

---

### SPDX and CycloneDX Formats

| **Aspect** | **SPDX** | **CycloneDX** |
|------------|----------|---------------|
| **Origin** | Linux Foundation | OWASP |
| **Focus** | Compliance & licensing | Security & vulnerability management |
| **Contents** | Package name, version, supplier, license, checksums, relationships, provenance | Components, versions, package URLs (purl), hashes, dependency relationships, metadata |
| **Serialization** | JSON, XML, RDF, tag-value | JSON, XML |
| **Use Cases** | License compliance, IP management, audits | Vulnerability detection, DevSecOps, CI/CD pipelines |

**Key Difference**:  
- **SPDX** → Rich detail for **legal and compliance**.  
- **CycloneDX** → Streamlined for **security and vulnerability tracking**.  

---

### Why SBOM Creation is Important
- **Transparency**: Know exactly what’s inside your software.  
- **Security**: Detect vulnerable components quickly.  
- **Compliance**: Meet regulatory requirements.  
- **Risk Management**: Identify outdated or risky dependencies.  
- **Trust**: Builds confidence with customers and regulators.  

---

### CVE Databases: NVD vs OSV

#### NVD (National Vulnerability Database)
- Managed by **NIST (U.S. government)**.  
- Uses **CPE (Common Platform Enumeration)** identifiers.  
- Provides CVSS scores, severity ratings, and detailed vulnerability metadata.  
- Broad coverage across commercial and open-source software.  

#### OSV (Open Source Vulnerabilities)
- Managed by **Google and the open-source community**.  
- Uses **Package URLs (purl)** for matching vulnerabilities to open-source packages.  
- Focused on open-source ecosystems (PyPI, npm, Maven, crates.io, etc.).  
- Provides version ranges affected and fixed versions.  

**Key Difference**:  
- **NVD** → Government-backed, broad coverage, CPE-based.  
- **OSV** → Community-driven, open-source focused, purl-based.  

---

## Step-by-Step Instructions

You will be required to design parsers for two ecosystems (Python and Java). The educational value is that you get to learn about differences in dependency management.

### 1. Set Up Project & Parser Framework

- Create a module with a **plugin-style architecture**, i.e., instead of writing one big parser, design the system so that each ecosystem (Python, Java, etc. for extension) has its own **plugin** (separate module).  Create separate modules (plugins) for each ecosystem. Example: `python_parser.py`, `java_parser.py`. Each plugin should follow the same interface so they can be swapped easily.  
- Each ecosystem parser must implement two functions (along with any others):
  - **`Detect(dir string) bool`:** Checks if the project directory belongs to that ecosystem (e.g., does it contain Python `.py` files or `requirements.txt` for Python, or `pom.xml` for Java?).  
  - **`Parse(dir string) ([]Package, error)`:** Reads the manifest and returns a list of packages with details.  

*What is a manifest file?:* Manifest files declare the intended dependencies of a project.
Examples: `requirements.txt` (Python), `pyproject.toml` (Python), `pom.xml` (Java).
They usually specify version ranges or constraints (e.g., numpy>=1.20,<2.0).
Think of them as the recipe — what you want to include.

- Define shared types:  Define common data structures that all parsers use:
  - **`Package`** → holds basic info: name, version, ecosystem, license, checksums.  
  - **`DependencyTree`** → represents a package and all its transitive dependencies.  
  - **`Vulnerability`** → stores CVE details: ID, severity, affected versions, fix version.  
These types make it possible to **unify data** from different ecosystems.

- Build a **command-line interface (CLI)** with subcommands such as:
  - **`scan`** → detect and parse dependencies.  
  - **`sbom`** → generate SBOMs in SPDX or CycloneDX format.  
  - **`check`** → query CVE databases and report vulnerabilities.  
This makes the tool usable in **real workflows and CI/CD pipelines**.

---

### 2. Build Dependency Parsers
- Implement parsers for **Python** (`requirements.txt`, `pyproject.toml`, `Pipfile.lock`, `uv.lock`) and **Java** (`pom.xml`, `build.gradle`).  
- Extract direct dependencies with version constraints from manifest files, if available, or generate the manifest files for projects.  
- Use **lockfiles** (Python and Java both support them), if available, to capture exact resolved versions.  
- Handle version constraint syntax: semver ranges, tilde, caret, wildcards.  

*What is a lockfile?:* Lockfiles record the exact versions of all dependencies (including transitive ones).
Examples: `Pipfile.lock` or `uv.lock` (Python). They ensure reproducibility — everyone installs the same versions.
Think of them as the shopping receipt — what you actually got.

---

### 3. Transitive Dependency Resolution
- For ecosystems with lockfiles: parse lockfiles directly.  
- For ecosystems without lockfiles: query package registry APIs.  
  - Python → PyPI JSON API  
- Build a **dependency graph**:  
  - Track direct vs transitive relationships  
  - Depth level  
  - Multiple versions (conflicts)  
- Implement **cycle detection** for circular dependencies.

---

### 4. License Detection & Metadata Enrichment
- Detect licenses via:  
  - Lockfiles (if included)  
  - Registry APIs  
  - Local source files (`LICENSE`, `COPYING`, SPDX headers)  
- Map license strings to **SPDX identifiers**.  
- Enrich metadata, e.g., download URL, homepage, maintainer info, SHA-256 checksums.  
- Flag:  
  - Missing licenses  
  - Copyleft licenses in proprietary projects  
  - Problematic licenses  

---

### 5A. Generate SPDX SBOMs
- Spend time revieweing and learning about SPDX.
- Implement **SPDX 3.0** generation in JSON and tag-value formats.  
- Map internal structures to SPDX concepts:  
  - Each package → `SPDXPackage`  
  - Relationships → `DEPENDS_ON`, `BUILD_TOOL_OF`, etc.  
- Include document metadata: creator tool, timestamp, namespace, CC0-1.0 license.  
- Validate against **SPDX JSON schema**.

---

### 5B. Generate CycloneDX SBOMs
- Can be done in-addition or in-replacement of 5A
- Spend time revieweing and learning about CycloneDX.
- Implement **CycloneDX 1.7** generation in JSON.  
- Map packages to `component` objects: type, name, version, purl, licenses, hashes.  
- Represent dependency tree with `dependencies` objects.  
- Include metadata: tool identification, manufacture date.  
- Validate against **CycloneDX JSON schema**.  
- Support both flat and hierarchical dependency views.

---

### 6. Vulnerability Scanner
- Integrate with:  
  - **NVD API** (CPE identifiers), and/or 
  - **OSV API** (Package URLs)  
- For each package:  
  - Query vulnerabilities  
  - Record CVE ID, CVSS score, severity, affected versions, fix version, description  
- Generate vulnerability report sorted by severity.  

---

## Key Concepts to Learn
- Purpose of SBOMs & regulatory requirements (**EO 14028**)  
- **SPDX vs CycloneDX** specification structures  
- Dependency resolution across ecosystems  
- Transitive dependency trees & supply chain depth  
- License compliance & SPDX identifiers  
- CVE databases (NVD, OSV) & vulnerability matching  

---

## Deliverables

### Submission Guidelines
- Submit the **project code files** along with the **Docker files** to your GitHub Classroom team repository.  
- Use Python and Java projects (either created or forked from the Internet) as input for your SBOM generation tool.
- Your tools should be able to parse a GitHub repo that the TA sends you the link for on the day of your demo.

---

### Project Requirements
In the demonstartion, you should be able to run CLI instruction(s) on a project directory. Your CLI tool should be able to:
- Scan the project and determine which parser ecosystem to use.  
- Parse the project and extract dependencies.  
- Generate for the TA:  
  - A **visual graph** of dependencies.  
  - **SPDX 3.0** and/or **CycloneDX 1.7** SBOMs.  
  - A **PDF report** (or otherwise) listing vulnerabilities, organized by severity (highest to lowest).  

This will require:
#### **Ecosystem Parsers & Dependency Extraction**
- Implement parsers for Python and Java.  
- Handle manifest and lockfile parsing.  
- Normalize extracted data into shared types (`Package`, `DependencyTree`).  
- Emphasis: Learn how different ecosystems manage dependencies and how to unify them.  

---

#### **SBOM Generation & Schema Validation**
- Generate SBOMs in **SPDX 3.0** and/or **CycloneDX 1.7** formats.  
- Validate generated SBOMs against official schemas.  
- Ensure compatibility with industry standards.  
- Emphasis: Learn compliance and security documentation standards, and how SBOMs support supply chain security.  

---

#### **Vulnerability Scanning & Security Analysis**
- Integrate with **NVD** and/or **OSV** databases.  
- Match dependencies to known CVEs.  
- Produce vulnerability reports sorted by severity.  
- Emphasis: Learn how vulnerabilities are tracked, how CVEs are structured, and how to automate risk assessment.  

---

#### **CLI Tool, Visualization & Reporting**
- Build the CLI with subcommands (`scan`, `sbom`, `check`).  
- Implement transitive dependency resolution.  
- Create a **visual graph** of dependencies.  
- Generate a **PDF report** with vulnerabilities and mitigation recommendations.  
- Emphasis: Learn usability, interactivity, and how to present cybersecurity insights effectively.  

---

## Recommended Libraries & Tools
- **CLI & Plugins** → `argparse`, `click`, `typer`, `abc`.  
- **Parsing** → `toml`, `requirements-parser`, `lxml`.
- **Querying registry APIs** → `requests`
- **Graphing** → `networkx`, `graphviz`, `matplotlib`, `seaborn`.  
- **SBOMs** → `spdx-tools`, `cyclonedx-python-lib`, `jsonschema`.  
- **Vulnerabilities** → `osv-python`, `nvdlib`.  
- **Reporting** → `reportlab`, `jinja2`m `fpdf`.

## Rubric

The rubric below outlines the **high-level expectations** for the project.  
A more detailed rubric — including **individual and team grading criteria** — will be shared with you soon.

Note that the required functionality has been split into **four subprojects**, each for you to assign to a different team member.  
- **Individual grading** will be based on each member’s contribution to their subproject.  
- **Collective team grading** will reflect the team’s ability to integrate all parts into a cohesive final product.
- Effective teamwork is essential to complete the project successfully. You must manage your time as a team by:  
  - Defining clear **task breakdowns**.  
  - Setting **timely milestones**.  
  - Performing **risk assessments** to anticipate and mitigate delays.  
- Use your **GitHub Classroom repository** for:  
  - Proper versioning of code and Docker files.  
  - Collaboration through branches and pull requests.  
  - Forking and reviewing project updates.  
  - Maintaining a transparent history of contributions.

## Levels
- **Level 3 (Excellent)** → Comprehensive, accurate, and professional execution  
- **Level 2 (Satisfactory)** → Functional but with gaps in depth, clarity, or polish  
- **Level 1 (Needs Improvement)** → Incomplete, unclear, or lacking core functionality  

---

## Criteria Table

| **Criterion**                | **Level 3 (Excellent)**                                                                 | **Level 2 (Satisfactory)**                                                   | **Level 1 (Needs Improvement)**                                     | **Mapped Sub-Project**                  |
|-------------------------------|-----------------------------------------------------------------------------------------|------------------------------------------------------------------------------|----------------------------------------------------------------------|-----------------------------------------|
| Demonstration & Presentation  | Clear, well-structured demo; CLI commands intuitive; dependency graph and SBOMs shown    | Demo shows basic functionality but lacks polish; CLI usable but limited       | Demo confusing/incomplete; CLI missing or unclear                     | CLI Tool, Visualization & Reporting      |
| Answering TA Questions        | Team confidently explains parsers, SBOM formats, CVE integration; precise and insightful | Team answers most questions but with limited detail or uncertainty            | Team struggles to answer; little understanding of code or concepts    | Ecosystem Parsers & Vulnerability Scanning |
| Technical Detail & Functionality | Code well-structured, documented, runs in Docker; all features implemented               | Code runs with minor bugs; most features implemented                          | Code fails to run; Docker missing; major features absent              | Ecosystem Parsers & SBOM Generation       |
| Ecosystem Parsers             | Python and Java parsers implemented; parsing accurate; normalized data | Parsers partially implemented; limited accuracy; normalization incomplete     | Parsers missing or unreliable; dependencies not extracted correctly   | Ecosystem Parsers & Dependency Extraction |
| SBOM Generation & Validation  | Generates valid SPDX and/or CycloneDX SBOMs; schema validation passes              | Generates SBOMs but with minor validation errors or incomplete metadata       | SBOM generation missing or invalid                                    | SBOM Generation & Schema Validation       |
| Dependency Graph Visualization| Graph shows transitive dependencies clearly; visualization intuitive and accurate       | Graph generated but limited clarity or missing transitive resolution          | Graph missing or incorrect; dependencies not visualized               | Dependency Graph & Visualization          |
| Vulnerability Scanning        | Integrates NVD and/or OSV; vulnerabilities matched accurately; severity ordering correct      | Vulnerability scanning works but simplistic; limited severity sorting         | Vulnerability scanning missing or inaccurate                          | Vulnerability Scanning & Security Analysis |
| Reporting & Output            | PDF report generated with vulnerabilities sorted by severity; clear mitigation notes     | PDF report generated but missing severity ordering or mitigation details      | Report missing or incomplete                                          | CLI Tool, Visualization & Reporting       |

---

## ✅ Scoring
- Each criterion scored **1–3 points**.  
- **Total possible score: 24 points**.  
- Suggested grading bands:  
  - 20–24 → Excellent (A)  
  - 14–19 → Satisfactory (B/C)  
  - ≤13 → Needs Improvement (D/F)  
