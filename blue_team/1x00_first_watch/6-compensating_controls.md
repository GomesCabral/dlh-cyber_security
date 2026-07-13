# Compensating Controls for the Legacy MRI Workstation

## 1. Risk Analysis

The MRI workstation runs Windows XP Embedded, an operating system that has not received security updates since 2014. Any known vulnerability affecting Windows XP remains exploitable, increasing the likelihood of compromise. Because the workstation is connected to the same VLAN as standard hospital workstations, an attacker who compromises another endpoint could move laterally to the MRI system or use it as a pivot to reach other critical systems. As a result, the risk extends beyond the Radiology department and affects the confidentiality, integrity and availability of the entire MedDefense network.

---

## 2. Compensating Control Strategy

### Control 1 – Network Segmentation

**Description:**  
Move the MRI workstation to a dedicated VLAN that only permits the minimum network communication required with the PACS server.

**Category:** Technical

**Function:** Compensating

**Risk Reduction:**  
Network segmentation limits lateral movement and reduces the attack surface without modifying the operating system.

**Limitations / Residual Risk:**  
The workstation remains vulnerable if an attacker gains access to the isolated network segment or compromises the PACS server.

---

### Control 2 – Firewall Access Control Rules

**Description:**  
Implement firewall rules that allow communication only between the MRI workstation and required systems such as the PACS server, while blocking all unnecessary inbound and outbound traffic.

**Category:** Technical

**Function:** Compensating

**Risk Reduction:**  
Restricting network communication reduces opportunities for attackers to exploit the workstation remotely.

**Limitations / Residual Risk:**  
Firewall rules cannot prevent attacks originating from authorized systems or exploitation of permitted services.

---

### Control 3 – Restricted Physical Access

**Description:**  
Limit physical access to the MRI control workstation to authorized Radiology personnel and monitor access to the room.

**Category:** Physical

**Function:** Preventive

**Risk Reduction:**  
Restricting physical access reduces the likelihood of unauthorized use or local compromise of the workstation.

**Limitations / Residual Risk:**  
Physical controls do not protect against remote attacks through the network.

---

## 3. Implementation Priority

If only one control could be implemented immediately, network segmentation would provide the greatest reduction in risk. Isolating the MRI workstation in a dedicated VLAN significantly reduces the possibility of lateral movement from compromised hospital workstations while preserving the network connectivity required for communication with the PACS server. This control delivers a substantial security improvement without modifying the certified operating system or interrupting clinical operations.
