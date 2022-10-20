docker build . --progress=plain -t maxday/fast_secret
dockerId=$(docker create maxday/fast_secret)
rm fast_secret.zip
rm -rf tmp
docker cp $dockerId:/fast_secret.zip .
unzip fast_secret.zip
