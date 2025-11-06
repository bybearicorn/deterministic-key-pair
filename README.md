# Hub is repository for Adrian

- Backend and frontend will be here
- All runs under single Dockerfile
- Backend serves /api and * is for frontend (or similar)
- Every single line of code here is sold to customers

## Build image locally

docker build -t hub-app .

## deps in hub-shared

There are deps in shared, that are only used by BE, cause FE only uses classes from api as types.
So I add them as peer dep in hub-shared, and devDep in FE, so everything works
