FROM nginx:alpine

# Copy the HTML file from templates folder
COPY templates/index.html /usr/share/nginx/html/index.html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]