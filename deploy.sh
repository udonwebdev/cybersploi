#!/bin/bash

# CYBERSPLOI Deployment Script
# Deploy to development, staging, or production environment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ENVIRONMENT=${1:-dev}
REGION=${2:-us-east-1}
VERSION=${3:-latest}

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}CYBERSPLOI Deployment Script${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${YELLOW}Environment:${NC} $ENVIRONMENT"
echo -e "${YELLOW}Region:${NC} $REGION"
echo -e "${YELLOW}Version:${NC} $VERSION"
echo ""

# Function to log messages
log_info() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
    exit 1
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# Function to check dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    
    commands=("docker" "docker-compose" "kubectl" "aws")
    for cmd in "${commands[@]}"; do
        if ! command -v $cmd &> /dev/null; then
            log_warning "$cmd not found - some features may be unavailable"
        fi
    done
    
    log_info "Dependencies check complete"
}

# Function to build Docker images
build_images() {
    log_info "Building Docker images..."
    
    docker build -t cybersploi-backend:$VERSION -f Dockerfile.backend .
    docker build -t cybersploi-frontend:$VERSION -f cybersploi/frontend/Dockerfile .
    
    log_info "Docker images built successfully"
}

# Function to run tests
run_tests() {
    log_info "Running tests..."
    
    # Backend tests
    docker run --rm -v $(pwd):/app cybersploi-backend:$VERSION pytest tests/ --cov=backend
    
    # Frontend tests
    cd cybersploi/frontend
    npm test -- --coverage --watchAll=false
    cd ../..
    
    log_info "All tests passed"
}

# Function to deploy to Docker Compose (dev environment)
deploy_dev() {
    log_info "Deploying to development environment..."
    
    # Build and start services
    docker-compose -f docker-compose.yml build --no-cache
    docker-compose -f docker-compose.yml up -d
    
    # Wait for services to be healthy
    sleep 10
    
    # Run migrations
    docker-compose exec -T backend python database/migrations.py
    
    # Check health
    log_info "Checking service health..."
    docker-compose ps
    
    echo ""
    log_info "Development environment deployed successfully!"
    echo ""
    echo -e "${BLUE}Access points:${NC}"
    echo "  Frontend:    http://localhost:3000"
    echo "  API:         http://localhost:8000"
    echo "  Prometheus:  http://localhost:9090"
    echo "  Grafana:     http://localhost:3001 (admin/admin)"
    echo "  Kibana:      http://localhost:5601"
}

# Function to deploy to Kubernetes
deploy_kubernetes() {
    log_info "Deploying to Kubernetes cluster..."
    
    if [ "$ENVIRONMENT" == "staging" ]; then
        NAMESPACE="staging"
    elif [ "$ENVIRONMENT" == "prod" ]; then
        NAMESPACE="production"
    else
        NAMESPACE="default"
    fi
    
    # Create namespace
    kubectl create namespace $NAMESPACE --dry-run=client -o yaml | kubectl apply -f -
    
    # Set current namespace
    kubectl config set-context --current --namespace=$NAMESPACE
    
    # Create ConfigMap
    kubectl create configmap cybersploi-config \
        --from-file=.env \
        -n $NAMESPACE \
        --dry-run=client -o yaml | kubectl apply -f -
    
    # Create Secrets
    kubectl create secret generic cybersploi-secrets \
        --from-literal=db-password=$(openssl rand -base64 32) \
        --from-literal=secret-key=$(openssl rand -base64 32) \
        -n $NAMESPACE \
        --dry-run=client -o yaml | kubectl apply -f -
    
    # Deploy services
    log_info "Deploying Kubernetes manifests..."
    kubectl apply -f k8s/namespace.yaml
    kubectl apply -f k8s/configmap.yaml
    kubectl apply -f k8s/secrets.yaml
    kubectl apply -f k8s/rbac.yaml
    kubectl apply -f k8s/storage.yaml
    kubectl apply -f k8s/database.yaml
    kubectl apply -f k8s/backend.yaml
    kubectl apply -f k8s/frontend.yaml
    kubectl apply -f k8s/ingress.yaml
    kubectl apply -f k8s/monitoring.yaml
    
    # Wait for deployments
    log_info "Waiting for deployments to be ready..."
    kubectl rollout status deployment/cybersploi-backend -n $NAMESPACE
    kubectl rollout status deployment/cybersploi-frontend -n $NAMESPACE
    
    log_info "Kubernetes deployment completed successfully!"
    
    # Show deployment info
    echo ""
    echo -e "${BLUE}Deployment Information:${NC}"
    kubectl get all -n $NAMESPACE
}

# Function to deploy to AWS ECS
deploy_ecs() {
    log_info "Deploying to AWS ECS..."
    
    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "AWS credentials not configured. Run 'aws configure' first."
    fi
    
    CLUSTER_NAME="cybersploi-$ENVIRONMENT"
    
    # Create ECS cluster if it doesn't exist
    aws ecs create-cluster --cluster-name $CLUSTER_NAME --region $REGION || true
    
    # Register task definitions
    aws ecs register-task-definition \
        --cli-input-json file://ecs/cybersploi-task-definition.json \
        --region $REGION
    
    # Create/update service
    aws ecs create-service \
        --cluster $CLUSTER_NAME \
        --service-name cybersploi-service \
        --task-definition cybersploi:1 \
        --desired-count 2 \
        --launch-type FARGATE \
        --region $REGION || \
    aws ecs update-service \
        --cluster $CLUSTER_NAME \
        --service cybersploi-service \
        --task-definition cybersploi:1 \
        --desired-count 2 \
        --region $REGION
    
    log_info "ECS deployment completed successfully!"
}

# Function to run smoke tests
run_smoke_tests() {
    log_info "Running smoke tests..."
    
    # Test API health
    API_URL="http://localhost:8000"
    
    response=$(curl -s -o /dev/null -w "%{http_code}" $API_URL/api/v1/health)
    if [ $response -eq 200 ]; then
        log_info "API health check passed"
    else
        log_error "API health check failed (HTTP $response)"
    fi
    
    # Test frontend
    FRONTEND_URL="http://localhost:3000"
    response=$(curl -s -o /dev/null -w "%{http_code}" $FRONTEND_URL)
    if [ $response -eq 200 ] || [ $response -eq 301 ]; then
        log_info "Frontend health check passed"
    else
        log_error "Frontend health check failed (HTTP $response)"
    fi
    
    log_info "All smoke tests passed"
}

# Function to show deployment status
show_status() {
    log_info "Deployment Status"
    echo ""
    
    if [ "$ENVIRONMENT" == "dev" ]; then
        echo "Docker Compose Services:"
        docker-compose ps
    elif [ "$ENVIRONMENT" == "staging" ] || [ "$ENVIRONMENT" == "prod" ]; then
        echo "Kubernetes Deployments:"
        kubectl get deployments
        echo ""
        echo "Kubernetes Services:"
        kubectl get services
        echo ""
        echo "Kubernetes Pods:"
        kubectl get pods
    fi
}

# Function to rollback deployment
rollback() {
    log_warning "Rolling back deployment..."
    
    if [ "$ENVIRONMENT" == "dev" ]; then
        docker-compose down
        docker-compose up -d
    elif [ "$ENVIRONMENT" == "staging" ] || [ "$ENVIRONMENT" == "prod" ]; then
        kubectl rollout undo deployment/cybersploi-backend
        kubectl rollout undo deployment/cybersploi-frontend
    fi
    
    log_info "Rollback completed"
}

# Function to display help
show_help() {
    echo "Usage: ./deploy.sh [environment] [region] [version]"
    echo ""
    echo "Environments:"
    echo "  dev       - Local development (Docker Compose)"
    echo "  staging   - Staging environment (Kubernetes)"
    echo "  prod      - Production environment (Kubernetes)"
    echo ""
    echo "Examples:"
    echo "  ./deploy.sh dev"
    echo "  ./deploy.sh staging us-east-1 v1.0.0"
    echo "  ./deploy.sh prod us-west-2 v1.0.0"
}

# Main deployment logic
main() {
    case $ENVIRONMENT in
        dev)
            check_dependencies
            build_images
            run_tests
            deploy_dev
            run_smoke_tests
            ;;
        staging|prod)
            check_dependencies
            build_images
            run_tests
            deploy_kubernetes
            run_smoke_tests
            ;;
        status)
            show_status
            ;;
        rollback)
            rollback
            ;;
        help)
            show_help
            ;;
        *)
            log_error "Unknown environment: $ENVIRONMENT. Use 'help' for usage information."
            ;;
    esac
}

# Run main function
main

log_info "Deployment script completed"
