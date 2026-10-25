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

# Project 1: DDoS Mitigation Tool

## TAs: Salma Kishk and Abdulrahman Abutur

## Overview
You will build a **network monitoring system** that detects Distributed Denial of Service (DDoS) attacks through traffic analysis, establishes baseline behavior patterns, and automatically implements rate limiting or firewall rules to mitigate attack impact.  

---

*What are DDoS attacks?* A DDoS attack employs multiple compromised systems (often part of a botnet) to flood a target—such as a website, server, or network—with massive amounts of traffic or requests. The goal is to overwhelm the target's resources (bandwidth, CPU, memory, or application capacity) so that legitimate users can no longer access the service.

*Types of DDoS attacks:*
- Volumetric attacks: Saturate bandwidth with huge amounts of traffic.
- Protocol attacks: Exploit weaknesses in network protocols (e.g., SYN floods).
- Application-layer attacks: Target specific services or applications with seemingly legitimate requests at abnormal rates.

*Impact of DDoS attacks:*
- Service disruption: Websites, applications, or APIs become unavailable.
- Financial loss: Downtime can cost businesses thousands to millions in lost revenue.
- Reputation damage: Customers lose trust if services are frequently unavailable.
- Operational strain: IT teams must divert resources to respond to the attack.

*Why detecting DDoS is important:*
- Early detection allows organizations to respond before the attack fully cripples services.
- Minimizes downtime by triggering automated defenses (e.g., rate limiting, filtering, rerouting).
- Protects users by ensuring legitimate traffic isn't blocked.
- Supports compliance with cybersecurity regulations and best practices.

*Where DDoS mitigation tools are used:*
- Cloud providers (AWS, Azure, Google Cloud) → protect hosted applications.
- Enterprise networks → safeguard internal systems and customer-facing services.
- ISPs and telecoms → defend infrastructure and prevent large-scale outages.
- Critical infrastructure (banks, hospitals, government services) → ensure essential services remain online.

--- 
 
This project teaches **network security**, **anomaly detection**, and demonstrates **defensive techniques** used by infrastructure providers and security operations centers.

---

## Step-by-Step Instructions

### 1. Learn about DDoS attacks
Spend some time learning about DDoS attack types and how to detect them. For example, 

**Detection approaches:**  
- Volumetric → obvious traffic spikes  
- Protocol → unusual packet patterns  
- Application → suspicious request rates  

---

### 2. Establish Traffic Baseline
- Obtain a dataset with DDoS data to build your tool for. You can use one of the publicly available datasets listed below or suggest another.
- Use a packet sniffing and/or traffic analysis tool to analyze the `pcap` files. A few are suggested below.
- Compute traffic statistics per time window, e.g., packet counts per protocol, source/destination IP distributions, port usage, bandwidth trends.  
- Store baseline metrics to capture normal traffic patterns.  
- Build statistical models (e.g., mean, std. deviation, percentiles, or machine learning, etc.) for anomaly detection.

---

### 3. Implement Anomaly Detection
- Compare against baseline patterns.  
- Flag deviations (e.g., traffic exceeds baseline mean by X).  
- Example indicators:  
  - Sudden traffic spikes  
  - Protocol distribution shifts  
  - Source IP concentration  
  - Port concentration  
- Combine different indicators/signals into a composite anomaly score.
- Optimize performance, e.g., rolling windows, incremental aggregation, sampling.

---

### 4. Automated Mitigation
- **Rate limiting**: Token bucket algorithm.  
- **Firewall rules**: Use `iptables` to block malicious sources.  
- **Safeguards**:  
  - Lenient rate limiting first  
  - Gradual restrictions  
  - Whitelist critical IPs  

---

### 5. Alerting
- Notify admins via **email, Slack, WhatsApp, or other system notifications**.  
- Include details: attack type, affected services, mitigation status, source IPs/countries.  
- Implement **alert ranking** to avoid notification fatigue.

---

### 6. Monitoring Dashboards
- Show real-time traffic stats, attack indicators, active mitigations, historical trends.  
- Example visualizations:  
  - Bandwidth usage  
  - Packet rates  
  - Protocol distribution  
  - Geographic attack sources  
- Provide admin controls: adjust rate limits, whitelist/blacklist IPs, trigger mitigations.

---

## Suggested Datasets
You can start with one of the following publicly available datasets, e.g.:
- [DDoS evaluation dataset; CIC-DDoS2019 (Canadian Institute for Cybersecurity, labeled DDoS traffic)  
](https://www.unb.ca/cic/datasets/ddos-2019.html)
- [CAIDA DDoS Attack Dataset (Center for Applied Internet Data Analysis)](https://www.caida.org/catalog/datasets/ddos-20070804_dataset/)

These datasets provide labeled attack vs. normal traffic, with which you can test your anomaly detection algorithms. 

---

## Deliverables

### Submission Guidelines
- Your team must submit the **project code files** along with the **Docker files** to your GitHub Classroom team repository.  
- Use the dataset to design your project, ensuring that part of the dataset is reserved for **testing and/or demonstration purposes**.  

---

### Dashboard Demonstration
During your presentation to the TA, you should showcase a **dashboard** that *simulates* real-time traffic monitoring using the dataset.  

#### Dashboard Features:
- **Time navigation**: Include a time slider (or otherwise) that allows movement between periods of normal traffic and periods with DDoS attacks.  
- **Alerts & anomaly detection**: When DDoS attacks are detected, the dashboard should:  
  - Flag deviations and indicators  
  - Display anomaly scores  
  - Recommend mitigation actions (with specific rate-limiting and IP table rules)
- **Notifications**: Functionality should allow sending alerts to the TA (via email, WhatsApp, or other channels).  

### Required Functionality
Your project must include:
#### **Baseline & Monitoring**
- Establish baseline traffic patterns  
- Implement traffic monitoring  
- Build rolling windows and efficient aggregation  

#### **Detection & Algorithms**
- Develop anomaly detection algorithms  
- Define thresholds and composite anomaly scores  
- Integrate detection logic with baseline monitoring  

#### **Mitigation & Firewall**
- Implement automated rate limiting (e.g., token bucket)  
- Generate and manage firewall rules (e.g., iptables integration)  
- Safeguards: whitelist critical IPs, gradual restrictions  

#### **Dashboard & Alerts**
- Build admin dashboard with time slider and visualizations  
- Display alerts, anomaly scores, and mitigation actions  
- Implement notification system (email, Slack, WhatsApp)  
- Ensure smooth TA demonstration with interactive controls  

---

## Recommended Libraries & Tools
- **Scapy / PyShark / dpkt** → packet sniffing & traffic analysis  
- **Pandas / NumPy** → statistical modeling & anomaly detection  
- **Matplotlib / Seaborn / Plotly** → dashboards & visualization  
- **iptables / ufw** → firewall rule automation  
- **Flask / Django / Streamlit / Plotly dash** → web-based monitoring dashboard  
- **Celery / APScheduler** → background monitoring & alerting tasks  
- **PyWA / SMTP** → alert notifications  

---

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

| **Criterion**              | **Level 3 (Excellent)**                                                                 | **Level 2 (Satisfactory)**                                                   | **Level 1 (Needs Improvement)**                                     | **Mapped Sub-Project**            |
|-----------------------------|-----------------------------------------------------------------------------------------|------------------------------------------------------------------------------|----------------------------------------------------------------------|-----------------------------------|
| Demonstration & Presentation | Clear, well-structured demo; dashboard intuitive; within time limit | Demo shows basic functionality but lacks polish; dashboard limited | Demo confusing/incomplete; dashboard missing; presentation disorganized | Dashboard & Alerts                |
| Answering TA Questions      | Confident, precise explanations; deep understanding of design and algorithms            | Answers most questions but limited detail; partial understanding              | Struggles to answer; little understanding of code/concepts            | Detection & Algorithms             |
| Technical Detail & Functionality | Code well-structured, documented, runs in Docker; all features implemented             | Code runs with minor bugs; most features implemented                          | Code fails to run; Docker missing; major features absent              | Baseline & Monitoring / Mitigation |
| Interactivity & Dashboard   | Interactive dashboard, anomaly visualization, admin controls           | Dashboard shows traffic/alerts but limited interactivity                      | Dashboard static or missing; no interactivity                         | Dashboard & Alerts                |
| Anomaly Detection Performance | Accurate detection; composite scores meaningful; false positives minimized              | Detection works but simplistic; thresholds hard-coded; moderate errors        | Detection unreliable/missing; anomalies not flagged                   | Detection & Algorithms             |
| Mitigation Strategy         | Automated rate limiting + firewall rules; safeguards included; clear recommendations    | Basic mitigation (rate limiting or firewall); limited safeguards              | Mitigation missing/ineffective; no safeguards                         | Mitigation & Firewall              |
| Alerting & Notifications    | Alerts; detailed anomaly info + mitigation actions                | Alerts functional but missing details                      | Alerts missing or non-functional                                     | Dashboard & Alerts                |
