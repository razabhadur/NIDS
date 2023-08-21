# NIDS

Cybersecurity Network Intrusion Detection System (NIDS)
Project Description
Welcome to the Cybersecurity Network Intrusion Detection System (NIDS) project repository. This project aims to develop a real-time Network Intrusion Detection System using machine learning techniques. The NIDS monitors network traffic, classifies it as normal or anomalous, and raises alerts for potential intrusion attempts.

Project Features
Real-Time Monitoring: The NIDS continuously captures and analyzes network packets in real time.

Machine Learning Classification: A Random Forest classifier is trained to distinguish between normal and anomalous network traffic.

Feature Extraction: Packet headers and payload are used to extract features for the classifier.

Anomaly Detection: The classifier identifies anomalous patterns and raises alerts when suspicious traffic is detected.

User Input: Users can input a domain name to monitor network traffic to/from that domain's IP address.

How to Use
Clone this repository to your local machine.

Install the required Python packages using the following command:

sh
Copy code
pip install -r requirements.txt
Run the nis.py script using a Python interpreter:

sh
Copy code
python nis.py
Follow the on-screen prompts to input the domain name for monitoring.

Prerequisites
Python 3.x
scikit-learn library
Network traffic capture capabilities (may require administrative privileges)
Contribution
Contributions to this project are welcome! Feel free to submit pull requests to enhance features, fix bugs, or improve documentation.

Disclaimer
This project is intended for educational and experimental purposes. It is not a production-grade system and should not be solely relied upon for security purposes.

License
This project is licensed under the MIT License.

