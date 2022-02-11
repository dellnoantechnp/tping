# Simply inherit the Python 3 image. 
FROM python:3.9

# change local time zone
cp /usr/share/zoneinfo/Asia/Shanghai    /etc/localtime

# Set an environment variable 
ENV APP /tping

# Create the directory
RUN mkdir $APP
WORKDIR $APP

# Copy the requirements file in order to install
# Python dependencies
COPY requirements.txt .

# Install Python dependencies
RUN pip install -r requirements.txt

# We copy the rest of the codebase into the image
COPY color.py .
COPY tping.py .

# Finally, we run tping help doc.
ENTRYPOINT ["python", "tping.py"]
CMD ["-h"]
