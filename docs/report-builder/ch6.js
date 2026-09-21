module.exports = [
['h1', 'CHAPTER SIX: SUMMARY, CONCLUSION AND RECOMMENDATIONS'],
['h2', '6.1 Introduction'],
['p', 'This chapter summarises the study, presents the major findings in relation to the research questions, draws conclusions, and makes recommendations to Liberia Telecommunications Corporation and suggestions for further research.'],

['h2', '6.2 Summary of the Study'],
['p', 'The study set out to design and implement a web-based phishing detection system for Liberia Telecommunications Corporation that accurately identifies phishing websites and warns users before they disclose sensitive information. Chapter One established that phishing is a growing threat to Internet users in Liberia and that LTC\'s existing, largely blacklist-based controls do not detect new phishing sites, do not protect its brand from imitation and provide no structured way to report and investigate phishing.'],
['p', 'Chapter Two reviewed Protection Motivation Theory, the Technology Acceptance Model and the DeLone and McLean IS Success Model, together with the concepts of URL-based, host- and content-based, heuristic and machine-learning detection, related studies and existing solutions, and identified a gap for an explainable, lightweight detection system tailored to a Liberian telecommunications organisation. Chapter Three analysed the existing system at LTC, proposed PhishGuard and described the design-science research approach, the incremental development methodology and the feasibility of the solution.'],
['p', 'Chapter Four specified 19 functional and 9 non-functional requirements and presented the three-tier architecture, use case and context models, a weighted detection model of 35 features in four groups, the report investigation workflow, and the database, interface and security designs. Chapter Five described the implementation using PHP 8.2, MariaDB, HTML5, CSS3 and JavaScript, presented the modules for the public, staff and administrators, and reported the results of unit, integration, functional, security and performance testing and of the accuracy evaluation.'],

['h2', '6.3 Summary of Findings'],
['p', 'The findings are summarised below according to the research questions.'],
['ol', [
  '**What are the common characteristics of phishing websites?** Phishing websites commonly use misleading domain structures (brand names in sub-domains or unrelated domains, look-alike characters, punycode), IP-address hosts, the "@" trick, abused top-level domains, URL shorteners, missing or newly issued certificates, credential-harvesting words such as "login", "verify" and "account", and pages with password forms that submit data to other domains.',
  '**How can website features be combined to detect phishing?** Assigning weighted risk points to features in four groups (reputation, lexical, host and content), summing them into a capped 0–100 score and classifying with two thresholds proved effective, fast and explainable. Brand-impersonation and look-alike checks driven by an organisation-managed trusted list were particularly effective for detecting domains imitating LTC and other trusted brands. Verifying that a domain actually exists, is registered and responds — using DNS-over-HTTPS and RDAP — ensures that made-up or taken-down links are never reported as safe, and reveals newly registered domains, a strong phishing indicator.',
  '**How can a web-based system support users, staff and administrators?** Separating the system into a public site, a staff area and an administrator console, each with its own navigation, allowed every user to see only what is relevant to them. Staff dashboards that show each person\'s position, responsibilities and assigned investigations, combined with the report–assign–finding–decision workflow, give LTC clear accountability and an audit trail for phishing incidents.',
  '**How can users be warned in real time?** A live URL-only check that runs as the user types (average 0.6 ms) and a full-screen alert on phishing verdicts warn users before any information is entered; explanations and recommended actions make the warnings actionable.',
  '**What level of accuracy can the system achieve?** On the 60-URL demonstration dataset the system achieved 100% accuracy, precision, recall and F1-score in its default configuration, and 90% accuracy with 100% precision and 80% recall in the strict configuration, with no false positives. These results are preliminary because the dataset is small and constructed; validation on large real-world datasets is required.',
]],

['h2', '6.4 Conclusion'],
['p', 'The study concludes that a lightweight, heuristic phishing detection system can effectively complement conventional security controls in an organisation such as Liberia Telecommunications Corporation. PhishGuard detects previously unseen phishing websites from their characteristics rather than relying solely on blacklists, identifies domains that imitate LTC and other trusted brands, warns users in real time and explains why a site is dangerous. Beyond detection, the system supports the organisation\'s response to phishing through a central reporting channel, staff dashboards with clearly defined responsibilities, an investigation workflow and built-in performance evaluation.'],
['p', 'All five specific objectives of the study were achieved. The system runs on free, widely available technologies and ordinary hardware, making it technically, economically and operationally feasible for LTC. Its main limitations are the preliminary nature of the accuracy evaluation, the dependence of the heuristic model on expert-selected weights, and the focus on web-based phishing.'],

['h2', '6.5 Recommendations'],
['p', 'Based on the findings, the following recommendations are made to Liberia Telecommunications Corporation:'],
['ol', [
  '**Adopt the system through a pilot:** deploy PhishGuard on an LTC server with HTTPS, first for the ICT and Customer Care departments, then for all staff and customers.',
  '**Validate on real data:** evaluate the system on large public datasets (for example PhishTank, OpenPhish or published academic datasets) and on phishing samples reported to LTC, and adjust weights and thresholds accordingly before full deployment.',
  '**Maintain the trusted-brand list:** keep LTC\'s own domains and those of partner banks, mobile-money providers and frequently imitated brands up to date, since they drive impersonation and look-alike detection.',
  '**Define responsibilities formally:** assign positions and responsibilities to all staff who handle phishing reports, and use the dashboards and report history to monitor response times.',
  '**Promote awareness:** link the scanner and awareness module from LTC\'s website, customer SMS and email communications, and include the quiz in staff induction and periodic training.',
  '**Integrate with existing controls:** feed confirmed phishing domains from PhishGuard into LTC\'s email filters, firewall and DNS filtering so that they are blocked across the network.',
  '**Enable Google Safe Browsing:** obtain a free Google Cloud API key and set it in the configuration so that every scan is also checked against the threat list used by Chrome.',
  '**Protect the system itself:** change the default administrator password, restrict administrator accounts, keep PHP and MySQL updated and back up the database regularly.',
]],

['h2', '6.6 Suggestions for Further Research'],
['p', 'The following areas are suggested for further research and development:'],
['ul', [
  '**Machine learning:** train classifiers such as Random Forest on the features and scan history collected by PhishGuard, and compare or combine them with the heuristic model.',
  '**Browser extension:** check pages automatically as users browse, instead of requiring them to paste addresses.',
  '**Other channels:** extend detection to links in SMS, WhatsApp and email messages, and to QR codes, which are increasingly used in Liberia.',
  '**Threat intelligence feeds:** integrate external reputation services and domain-registration (WHOIS) age to strengthen host-based detection.',
  '**Visual similarity:** compare screenshots of suspicious pages with LTC\'s genuine pages to detect cloned login and billing pages.',
  '**User studies:** measure how PhishGuard\'s warnings and awareness module change the security behaviour of LTC staff and customers over time.',
]],

['h2', '6.7 Chapter Summary'],
['p', 'This chapter summarised the study, presented the findings for each research question, concluded that the objectives were achieved and that PhishGuard is a feasible and useful complement to LTC\'s existing security controls, and made recommendations for deployment, validation and further research.'],
];
