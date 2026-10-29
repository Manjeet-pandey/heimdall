FROM python:3.12-slim
RUN pip install --no-cache-dir torch==2.5.1 --index-url https://download.pytorch.org/whl/cpu \
 && pip install --no-cache-dir transformers==4.46.3 sentencepiece==0.2.0 protobuf==5.28.3
# Named volume mounted here inherits this ownership, so the non-root user can fill the HF cache.
RUN mkdir /hf && chown 10000:10000 /hf
