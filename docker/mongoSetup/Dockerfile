FROM epicsbase

ADD ./mongoSetup /mongoSetup
WORKDIR /mongoSetup
ENV UV_LINK_MODE=copy

RUN --mount=type=cache,target=/usr/local/uv/.cache/uv \
    uv sync

CMD ["uv", "run", "main.py"]
