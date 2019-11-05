FROM python:3.7-slim

# Create app directory
RUN mkdir -p /app
WORKDIR /app

# Bundle app source
COPY awaf_policy_validator/ /app/
COPY awaf-policy-validator.py requirements.txt /app/

# Install packages
RUN pip install -r requirements.txt

CMD [ "python", "awaf-policy-validator.py" ]