# ── Estágio 1: compilação ──────────────────────────────────────────────────────
FROM eclipse-temurin:21-jdk-alpine AS build

WORKDIR /app

# copia os fontes e compila todos os .java de uma vez
COPY src/ src/
RUN mkdir -p out \
    && find src -name "*.java" > sources.txt \
    && javac -d out @sources.txt

# ── Estágio 2: imagem de execução (menor, só JRE) ─────────────────────────────
FROM eclipse-temurin:21-jre-alpine

WORKDIR /app

COPY --from=build /app/out ./out

# MAIN_CLASS é definida por cada serviço no docker-compose
ENV MAIN_CLASS=Cliente.Cliente

CMD ["sh", "-c", "java -cp out ${MAIN_CLASS}"]