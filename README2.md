# SecureGate - Cloud-Native Enterprise Architecture 🚀

A comprehensive migration of an academic Python Flask application into a resource-optimized, fully automated, and orchestrated microservices pipeline. 

## 🏗️ Architecture Stack & Strategy
Given local hardware constraints (**Intel i3, 8GB RAM**), this project was engineered using a lightweight **Infrastructure-as-Code** strategy to decouple dependencies and optimize computing metrics:

1. **Local Linux Environment:** Managed execution planes via **WSL2 (Ubuntu Linux)** to keep host system overhead minimal.
2. **Containerization:** Architected an optimized multi-stage `Dockerfile` leveraging a lightweight **Python Alpine** base image to minimize disk footprint and enhance container security boundaries.
3. **Multi-Container Composition:** Utilized **Docker Compose** to cleanly isolate the Flask core backend engine from persistent storage access streams.
4. **CI/CD Automation:** Integrated an automated **GitHub Actions** cloud workflow (`.github/workflows/docker-build.yml`) to automatically pull code, execute test routines, and verify Docker image compliance on every push event.
5. **Cluster Orchestration:** Authored declarative Kubernetes manifests (`k8s/deployment.yaml` & `k8s/service.yaml`) to define a high-availability layout running **3 self-healing replicas** behind a smart **NodePort Load Balancer**.

## 📂 Project Repository Structure
* `/k8s` - Declarative Kubernetes workload and networking specifications.
* `.github/workflows` - Automated cloud compilation and validation rules.
* `Dockerfile` - Optimized base-image environment blueprints.
* `docker-compose.yml` - Multi-service local networking architectures.
* `app.py` - Flask backend service.
