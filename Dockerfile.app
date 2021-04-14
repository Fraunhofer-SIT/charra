##############################################################################
# "Dockerfile"                                                               #
#                                                                            #
# Author: Michael Eckel <michael.eckel@sit.fraunhofer.de>                    #
# Date: 2019-06-26                                                           #
#                                                                            #
# Hint: Check your Dockerfile at https://www.fromlatest.io/                  #
##############################################################################

FROM fraunhofer-sit/charra-dev-env:1.5.1 AS base
LABEL maintainer="Michael Eckel <michael.eckel@sit.fraunhofer.de>"

## set environment variables
USER "$uid:$gid"
ENV HOME /home/"$user"
WORKDIR /home/"$user"

## compile CHARRA
COPY ./ /home/bob/charra
WORKDIR /home/bob/charra
RUN make -j

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["/bin/bash"]
