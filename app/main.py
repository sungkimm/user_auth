import config
from fastapi import Depends, FastAPI
from routers import authentication, token, social_oauth



# dependency added to app will be applied to every routers
# app = FastAPI(dependencies=[Depends(test)])
app = FastAPI()

app.include_router(authentication.router)
app.include_router(token.router)
app.include_router(social_oauth.router)


@app.get("/")
async def root():
    return {"health": "good"}
